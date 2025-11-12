import * as SelectPrimitive from "@radix-ui/react-select";
import { Check, ChevronDown } from "lucide-react";
import { forwardRef } from "react";
import { cn } from "../../lib/utils";

export const Select = SelectPrimitive.Root;
export const SelectValue = SelectPrimitive.Value;

export const SelectTrigger = forwardRef<HTMLButtonElement, SelectPrimitive.SelectTriggerProps>(
  ({ className, children, ...props }, ref) => (
    <SelectPrimitive.Trigger
      ref={ref}
      className={cn(
        "flex h-10 w-full items-center justify-between rounded-md border border-slate-700 bg-slate-950 px-3 text-sm text-slate-100 focus:outline-none focus:ring-2 focus:ring-emerald-500",
        className
      )}
      {...props}
    >
      {children}
      <ChevronDown className="ml-2 h-4 w-4" aria-hidden />
    </SelectPrimitive.Trigger>
  )
);
SelectTrigger.displayName = SelectPrimitive.Trigger.displayName;

export const SelectContent = forwardRef<HTMLDivElement, SelectPrimitive.SelectContentProps>(
  ({ className, children, ...props }, ref) => (
    <SelectPrimitive.Content
      ref={ref}
      className={cn("z-50 min-w-[8rem] overflow-hidden rounded-md border border-slate-800 bg-slate-900 shadow-md", className)}
      {...props}
    >
      <SelectPrimitive.Viewport className="p-2 text-sm text-slate-100">
        {children}
      </SelectPrimitive.Viewport>
    </SelectPrimitive.Content>
  )
);
SelectContent.displayName = SelectPrimitive.Content.displayName;

export const SelectItem = forwardRef<HTMLDivElement, SelectPrimitive.SelectItemProps>(
  ({ className, children, ...props }, ref) => (
    <SelectPrimitive.Item
      ref={ref}
      className={cn(
        "relative flex cursor-pointer select-none items-center rounded-sm px-2 py-1.5 text-sm text-slate-100 focus:bg-slate-800 focus:outline-none",
        className
      )}
      {...props}
    >
      <SelectPrimitive.ItemIndicator className="absolute left-2 flex h-3.5 w-3.5 items-center justify-center">
        <Check className="h-4 w-4" aria-hidden />
      </SelectPrimitive.ItemIndicator>
      <SelectPrimitive.ItemText>{children}</SelectPrimitive.ItemText>
    </SelectPrimitive.Item>
  )
);
SelectItem.displayName = SelectPrimitive.Item.displayName;
