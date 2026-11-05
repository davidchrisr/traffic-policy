<script lang="ts">
  import { LogOut } from "@lucide/svelte";
  import { Button } from "#lib/components/ui/button/index.ts";
  import * as Dialog from "#lib/components/ui/dialog/index.ts";

  let { onSignOut }: { onSignOut: () => Promise<void> } = $props();

  let open = $state(false),
    signingOut = $state(false),
    error = $state("");

  async function signOut() {
    if (signingOut) return;
    signingOut = true;
    error = "";

    try {
      await onSignOut();
      open = false;
    } catch {
      error = "Sign-out could not be completed. Try again.";
    } finally {
      signingOut = false;
    }
  }
</script>

<Dialog.Root
  bind:open
  onOpenChange={(isOpen) => {
    if (isOpen) error = "";
  }}
>
  <Dialog.Trigger>
    {#snippet child({ props })}
      <Button {...props} variant="outline">
        <LogOut size={16} />Sign out
      </Button>
    {/snippet}
  </Dialog.Trigger>
  <Dialog.Content
    showCloseButton={!signingOut}
    onOpenAutoFocus={(event) => {
      event.preventDefault();
      document
        .querySelector<HTMLButtonElement>("[data-signout-cancel]")
        ?.focus();
    }}
    onEscapeKeydown={(event) => {
      if (signingOut) event.preventDefault();
    }}
    onInteractOutside={(event) => {
      if (signingOut) event.preventDefault();
    }}
  >
    <Dialog.Header
      ><Dialog.Title>Sign out?</Dialog.Title><Dialog.Description
        >Unsaved changes will be lost. Sign in again to manage traffic rules.</Dialog.Description
      ></Dialog.Header
    >
    {#if error}<p class="field-error" role="alert">{error}</p>{/if}
    <Dialog.Footer>
      <Button
        data-signout-cancel
        variant="ghost"
        disabled={signingOut}
        onclick={() => (open = false)}>Cancel</Button
      >
      <Button variant="outline" disabled={signingOut} onclick={signOut}
        >{signingOut ? "Signing out…" : "Sign out"}</Button
      >
    </Dialog.Footer>
  </Dialog.Content>
</Dialog.Root>
