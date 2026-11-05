<script lang="ts">
  import type { Snippet } from "svelte";
  import { MediaQuery } from "svelte/reactivity";
  import { Dialog as DialogPrimitive } from "bits-ui";
  import { X } from "@lucide/svelte";
  import { Button } from "#lib/components/ui/button/index.ts";
  import * as Dialog from "#lib/components/ui/dialog/index.ts";
  import PaneResizer from "#lib/components/PaneResizer.svelte";

  // Beside the list on wide screens; a bottom sheet below the split-view breakpoint in app.css.
  let {
    label,
    open = $bindable(false),
    children,
  }: { label: string; open?: boolean; children: Snippet } = $props();

  const narrow = new MediaQuery("max-width: 900px");

  let pane = $state<HTMLElement>(),
    width = $state<number>();

  $effect(() => {
    if (!narrow.current) open = false;
  });
</script>

{#if narrow.current}<Dialog.Root bind:open>
    <Dialog.Portal>
      <Dialog.Overlay />
      <DialogPrimitive.Content
        aria-label={label}
        data-slot="inspector-sheet"
        class="inspector-sheet data-open:animate-in data-closed:animate-out data-open:slide-in-from-bottom data-closed:slide-out-to-bottom motion-reduce:animate-none duration-200 outline-none"
      >
        <div class="flex justify-end">
          <DialogPrimitive.Close>
            {#snippet child({ props })}<Button
                variant="ghost"
                size="icon-sm"
                {...props}><X /><span class="sr-only">Close</span></Button
              >{/snippet}
          </DialogPrimitive.Close>
        </div>
        {@render children()}
      </DialogPrimitive.Content>
    </Dialog.Portal>
  </Dialog.Root>{:else}<div
    class="inspector-pane"
    style:--inspector-width={width === undefined ? undefined : `${width}px`}
    bind:this={pane}
  >
    <PaneResizer
      label={`Resize ${label.toLowerCase()}`}
      {pane}
      side="end"
      min={320}
      max={(element) => element.parentElement!.clientWidth / 2}
      storageKey="traffic-policy.inspector-width"
      bind:width
    />
    <aside class="inspector" aria-label={label}>
      {@render children()}
    </aside>
  </div>{/if}
