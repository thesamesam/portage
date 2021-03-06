# Copyright 1999-2020 Gentoo Authors
# Distributed under the terms of the GNU General Public License v2

import signal

from portage import os
from portage.util.futures import asyncio
from portage.util.futures.compat_coroutine import coroutine, coroutine_return
from portage.util.SlotObject import SlotObject

class AsynchronousTask(SlotObject):
	"""
	Subclasses override _wait() and _poll() so that calls
	to public methods can be wrapped for implementing
	hooks such as exit listener notification.

	Sublasses should call self._async_wait() to notify exit listeners after
	the task is complete and self.returncode has been set.
	"""

	__slots__ = ("background", "cancelled", "returncode", "scheduler") + \
		("_exit_listener_handles", "_exit_listeners", "_start_listeners")

	_cancelled_returncode = - signal.SIGINT

	@coroutine
	def async_start(self):
		try:
			if self._was_cancelled():
				raise asyncio.CancelledError
			yield self._async_start()
			if self._was_cancelled():
				raise asyncio.CancelledError
		except asyncio.CancelledError:
			self.cancel()
			self._was_cancelled()
			self._async_wait()
			raise
		finally:
			self._start_hook()

	@coroutine
	def _async_start(self):
		self._start()
		coroutine_return()
		yield None

	def start(self):
		"""
		Start an asynchronous task and then return as soon as possible.
		"""
		self._start()
		self._start_hook()

	def _start(self):
		self.returncode = os.EX_OK
		self._async_wait()

	def async_wait(self):
		"""
		Wait for returncode asynchronously. Notification is available
		via the add_done_callback method of the returned Future instance.

		@returns: Future, result is self.returncode
		"""
		waiter = self.scheduler.create_future()
		exit_listener = lambda self: waiter.cancelled() or waiter.set_result(self.returncode)
		self.addExitListener(exit_listener)
		waiter.add_done_callback(lambda waiter:
			self.removeExitListener(exit_listener) if waiter.cancelled() else None)
		if self.returncode is not None:
			# If the returncode is not None, it means the exit event has already
			# happened, so use _async_wait() to guarantee that the exit_listener
			# is called. This does not do any harm because a given exit listener
			# is never called more than once.
			self._async_wait()
		return waiter

	def isAlive(self):
		return self.returncode is None

	def poll(self):
		if self.returncode is not None:
			return self.returncode
		self._poll()
		self._wait_hook()
		return self.returncode

	def _poll(self):
		return self.returncode

	def wait(self):
		"""
		Wait for the returncode attribute to become ready, and return
		it. If the returncode is not ready and the event loop is already
		running, then the async_wait() method should be used instead of
		wait(), because wait() will raise asyncio.InvalidStateError in
		this case.

		@rtype: int
		@returns: the value of self.returncode
		"""
		if self.returncode is None:
			if self.scheduler.is_running():
				raise asyncio.InvalidStateError('Result is not ready.')
			self.scheduler.run_until_complete(self.async_wait())
		self._wait_hook()
		return self.returncode

	def _async_wait(self):
		"""
		For cases where _start exits synchronously, this method is a
		convenient way to trigger an asynchronous call to self.wait()
		(in order to notify exit listeners), avoiding excessive event
		loop recursion (or stack overflow) that synchronous calling of
		exit listeners can cause. This method is thread-safe.
		"""
		self.scheduler.call_soon(self.wait)

	def cancel(self):
		"""
		Cancel the task, but do not wait for exit status. If asynchronous exit
		notification is desired, then use addExitListener to add a listener
		before calling this method.
		NOTE: Synchronous waiting for status is not supported, since it would
		be vulnerable to hitting the recursion limit when a large number of
		tasks need to be terminated simultaneously, like in bug #402335.
		"""
		if not self.cancelled:
			self.cancelled = True
			self._cancel()

	def _cancel(self):
		"""
		Subclasses should implement this, as a template method
		to be called by AsynchronousTask.cancel().
		"""
		pass

	def _was_cancelled(self):
		"""
		If cancelled, set returncode if necessary and return True.
		Otherwise, return False.
		"""
		if self.cancelled:
			if self.returncode is None:
				self.returncode = self._cancelled_returncode
			return True
		return False

	def addStartListener(self, f):
		"""
		The function will be called with one argument, a reference to self.
		"""
		if self._start_listeners is None:
			self._start_listeners = []
		self._start_listeners.append(f)

		# Ensure that start listeners are always called.
		if self.returncode is not None:
			self._start_hook()

	def removeStartListener(self, f):
		if self._start_listeners is None:
			return
		self._start_listeners.remove(f)

	def _start_hook(self):
		if self._start_listeners is not None:
			start_listeners = self._start_listeners
			self._start_listeners = None

			for f in start_listeners:
				self.scheduler.call_soon(f, self)

	def addExitListener(self, f):
		"""
		The function will be called with one argument, a reference to self.
		"""
		if self._exit_listeners is None:
			self._exit_listeners = []
		self._exit_listeners.append(f)
		if self.returncode is not None:
			self._wait_hook()

	def removeExitListener(self, f):
		if self._exit_listeners is not None:
			try:
				self._exit_listeners.remove(f)
			except ValueError:
				pass

		if self._exit_listener_handles is not None:
			handle = self._exit_listener_handles.pop(f, None)
			if handle is not None:
				handle.cancel()

	def _wait_hook(self):
		"""
		Call this method after the task completes, just before returning
		the returncode from wait() or poll(). This hook is
		used to trigger exit listeners when the returncode first
		becomes available.
		"""
		# Ensure that start listeners are always called.
		if self.returncode is not None:
			self._start_hook()

		if self.returncode is not None and \
			self._exit_listeners is not None:

			listeners = self._exit_listeners
			self._exit_listeners = None
			if self._exit_listener_handles is None:
				self._exit_listener_handles = {}

			for listener in listeners:
				if listener not in self._exit_listener_handles:
					self._exit_listener_handles[listener] = \
						self.scheduler.call_soon(self._exit_listener_cb, listener)

	def _exit_listener_cb(self, listener):
		del self._exit_listener_handles[listener]
		listener(self)
