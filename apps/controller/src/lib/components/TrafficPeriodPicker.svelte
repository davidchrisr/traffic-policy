<script lang="ts">
  import { ChevronDown, CircleArrowRight } from "@lucide/svelte";
  import { Button } from "#lib/components/ui/button/index.ts";
  import * as DropdownMenu from "#lib/components/ui/dropdown-menu/index.ts";
  import { trafficPeriods } from "#lib/traffic-period.ts";
  import { formatFullInstant } from "#lib/format-time.ts";

  let {
    value = $bindable("300"),
    since = $bindable(Date.now()),
    id,
  }: { value: string; since: number; id?: string } = $props();

  const label = $derived(
    value === "from-now"
      ? "From now"
      : trafficPeriods.find((period) => period.value === value)!.label,
  );
</script>

<DropdownMenu.Root>
  <DropdownMenu.Trigger {id}>
    {#snippet child({ props })}
      <Button
        {...props}
        variant="outline"
        class="w-48 max-w-full justify-between"
        aria-label="Traffic period"
        title={value === "from-now"
          ? `Traffic recorded since ${formatFullInstant(new Date(since).toISOString())}. Select From now again to restart the window.`
          : undefined}
        ><span class="min-w-0 truncate">{label}</span><ChevronDown
          size={14}
        /></Button
      >
    {/snippet}
  </DropdownMenu.Trigger>
  <DropdownMenu.Content align="start">
    <DropdownMenu.RadioGroup bind:value>
      <DropdownMenu.RadioItem value="all" closeOnSelect
        >Show all</DropdownMenu.RadioItem
      >
      <DropdownMenu.Separator />
      {#each trafficPeriods.slice(1) as period (period.value)}<DropdownMenu.RadioItem
          value={period.value}
          closeOnSelect>{period.label}</DropdownMenu.RadioItem
        >{/each}
      <DropdownMenu.Separator />
      <DropdownMenu.RadioItem
        value="from-now"
        closeOnSelect
        onSelect={() => (since = Date.now())}
        ><CircleArrowRight size={16} />From now</DropdownMenu.RadioItem
      >
    </DropdownMenu.RadioGroup>
  </DropdownMenu.Content>
</DropdownMenu.Root>
