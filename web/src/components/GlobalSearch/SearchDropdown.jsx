import { Fragment } from 'react'
import { Transition } from '@headlessui/react'

export default function SearchDropdown({ isOpen, children }) {
  return (
    <Transition
      show={isOpen}
      as={Fragment}
      enter="transition ease-out duration-100"
      enterFrom="opacity-0 translate-y-1"
      enterTo="opacity-100 translate-y-0"
      leave="transition ease-in duration-75"
      leaveFrom="opacity-100 translate-y-0"
      leaveTo="opacity-0 translate-y-1"
    >
      <div className="absolute left-0 right-0 z-50 mt-1 max-h-[480px] overflow-y-auto rounded-xl border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-800 shadow-2xl">
        {children}
      </div>
    </Transition>
  )
}
