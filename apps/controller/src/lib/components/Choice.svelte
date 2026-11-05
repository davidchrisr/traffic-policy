<script lang="ts">
  import type { Component } from "svelte";
  import * as Select from "#lib/components/ui/select/index.ts";

  // An icon shown before an option's label; the label stays the accessible name.
  interface Option {
    value: string;
    label: string;
    icon?: Component<{ size?: number; class?: string }>;
    iconClass?: string;
  }

  let {
    value = $bindable(""),
    options,
    id,
    label,
    disabled = false,
    fullWidth = false,
  }: {
    value: string;
    options: Option[];
    id?: string;
    label: string;
    disabled?: boolean;
    fullWidth?: boolean;
  } = $props();

  const current = $derived(options.find((option) => option.value === value));

  const selected = $derived(current?.label ?? "Choose a value");
</script>

<Select.Root type="single" bind:value {disabled}>
  <Select.Trigger
    {id}
    aria-label={label}
    class={fullWidth ? "w-full min-w-0" : "w-48 min-w-0 max-w-full"}
    >{#if current?.icon}<current.icon
        size={15}
        class={current.iconClass}
      />{/if}<span class="min-w-0 flex-1 truncate text-left" title={selected}
      >{selected}</span
    ></Select.Trigger
  >
  <Select.Content align="start" class="w-(--bits-select-anchor-width) min-w-0"
    >{#each options as option (option.value)}<Select.Item
        value={option.value}
        label={option.label}
        >{#if option.icon}<option.icon
            size={15}
            class={option.iconClass}
          />{/if}{option.label}</Select.Item
      >{/each}</Select.Content
  >
</Select.Root>
