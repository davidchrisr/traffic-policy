<script lang="ts">
  import { untrack } from "svelte";
  import { failureMessage } from "#lib/client.ts";
  import * as Dialog from "#lib/components/ui/dialog/index.ts";
  import { Button } from "#lib/components/ui/button/index.ts";
  import { Input } from "#lib/components/ui/input/index.ts";
  import { Label } from "#lib/components/ui/label/index.ts";

  // Names a rule set to create or rename.
  let {
    open = $bindable(false),
    title,
    description = null,
    initial = "",
    action,
    onSubmit,
  }: {
    open: boolean;
    title: string;
    description?: string | null;
    initial?: string;
    action: string;
    onSubmit: (name: string) => Promise<void>;
  } = $props();

  let name = $state(""),
    busy = $state(false),
    error = $state("");

  $effect(() => {
    if (!open) return;
    name = untrack(() => initial);
    error = "";
  });

  async function submit() {
    if (busy) return;
    busy = true;
    error = "";

    try {
      await onSubmit(name.trim());
      open = false;
    } catch (failure) {
      error = failureMessage(failure, "Rule set could not be saved");
    } finally {
      busy = false;
    }
  }
</script>

<Dialog.Root bind:open>
  <Dialog.Content
    showCloseButton={!busy}
    onEscapeKeydown={(event) => {
      if (busy) event.preventDefault();
    }}
    onInteractOutside={(event) => {
      if (busy) event.preventDefault();
    }}
  >
    <Dialog.Header
      ><Dialog.Title>{title}</Dialog.Title>{#if description}<Dialog.Description
          >{description}</Dialog.Description
        >{/if}</Dialog.Header
    >
    <form
      class="space-y-4"
      onsubmit={(event) => {
        event.preventDefault();
        void submit();
      }}
    >
      <div class="field-group">
        <Label for="rule-set-name">Name</Label><Input
          id="rule-set-name"
          bind:value={name}
          maxlength={128}
          required
        />
      </div>
      {#if error}<p class="field-error" role="alert">{error}</p>{/if}
      <Dialog.Footer
        ><Button
          variant="ghost"
          type="button"
          disabled={busy}
          onclick={() => (open = false)}>Cancel</Button
        ><Button type="submit" disabled={busy || !name.trim()}
          >{busy ? "Saving…" : action}</Button
        ></Dialog.Footer
      >
    </form>
  </Dialog.Content>
</Dialog.Root>
