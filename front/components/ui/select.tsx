import * as React from "react";
import { Listbox, Transition } from "@headlessui/react";
import { ChevronDownIcon } from "@heroicons/react/solid";
import { Fragment } from "react";

export function Select({ children, ...props }) {
  return <Listbox {...props}>{children}</Listbox>;
}

export function SelectTrigger({ children, ...props }) {
  return (
    <Listbox.Button {...props} className="relative w-full cursor-pointer rounded-md border border-gray-300 bg-white py-2 pl-3 pr-10 text-left shadow-sm focus:border-indigo-500 focus:outline-none focus:ring-1 focus:ring-indigo-500 sm:text-sm">
      {children}
      <span className="pointer-events-none absolute inset-y-0 right-0 flex items-center pr-2">
        <ChevronDownIcon className="h-5 w-5 text-gray-400" aria-hidden="true" />
      </span>
    </Listbox.Button>
  );
}

export function SelectContent({ children, ...props }) {
  return (
    <Transition
      as={Fragment}
      leave="transition ease-in duration-100"
      leaveFrom="opacity-100"
      leaveTo="opacity-0"
    >
      <Listbox.Options {...props} className="absolute mt-1 max-h-60 w-full overflow-auto rounded-md bg-white py-1 text-base shadow-lg ring-1 ring-black ring-opacity-5 focus:outline-none sm:text-sm">
        {children}
      </Listbox.Options>
    </Transition>
  );
}

export function SelectItem({ children, ...props }) {
  return (
    <Listbox.Option
      {...props}
      className={({ active }) =>
        `${active ? 'text-white bg-indigo-600' : 'text-gray-900'}
                cursor-default select-none relative py-2 pl-10 pr-4`
      }
    >
      {({ selected }) => (
        <>
          <span
            className={`${selected ? 'font-medium' : 'font-normal'} block truncate`}
          >
            {children}
          </span>
          {selected ? (
            <span
              className={`text-indigo-600 absolute inset-y-0 left-0 flex items-center pl-3`}
            >
              <CheckIcon className="h-5 w-5" aria-hidden="true" />
            </span>
          ) : null}
        </>
      )}
    </Listbox.Option>
  );
}

export function SelectValue({ children, ...props }) {
  return (
    <span {...props} className="block truncate">
      {children}
    </span>
  );
}

function CheckIcon(props) {
  return (
    <svg
      {...props}
      xmlns="http://www.w3.org/2000/svg"
      fill="none"
      viewBox="0 0 24 24"
      stroke="currentColor"
      aria-hidden="true"
    >
      <path
        strokeLinecap="round"
        strokeLinejoin="round"
        strokeWidth="2"
        d="M5 13l4 4L19 7"
      />
    </svg>
  );
}