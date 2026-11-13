<script lang="ts">
  import type { RuleSetFile } from "@traffic-policy/contracts";
  import { failureMessage } from "#lib/client.ts";
  import { readRuleSetFile } from "#lib/rule-sets.ts";
  import * as Dialog from "#lib/components/ui/dialog/index.ts";
  import { Button } from "#lib/components/ui/button/index.ts";
  import { Input } from "#lib/components/ui/input/index.ts";
  import { Label } from "#lib/components/ui/label/index.ts";

  // Reads an exported rule set file and imports it as a new rule set. `submit` sends the import
  // and resolves once it is saved.
  let {
    open = $bindable(false),
    submit: send,
  }: {
    open: boolean;
    submit: (file: RuleSetFile, name: string) => Promise<void>;
  } = $props();

  let file = $state<RuleSetFile | null>(null),
    name = $state(""),
    busy = $state(false),
    error = $state("");

  $effect(() => {
    if (!open) return;
    file = null;
    name = "";
    error = "";
  });

  async function read(event: Event & { currentTarget: HTMLInputElement }) {
    file = null;
    error = "";
    const chosen = event.currentTarget.files?.[0];

    if (!chosen) return;
    file = readRuleSetFile(await chosen.text());

    if (file) name = file.name;
    else error = "This file is not a rule set export";
  }

  async function submit() {
    if (busy || !file) return;
    busy = true;
    error = "";

    try {
      await send(file, name.trim());
      open = false;
    } catch (failure) {
      error = failureMessage(failure, "Rule set could not be imported");
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
    <Dialog.Header><Dialog.Title>Import rule set</Dialog.Title></Dialog.Header>
    <form
      class="space-y-4"
      onsubmit={(event) => {
        event.preventDefault();
        void submit();
      }}
    >
      <div class="field-group">
        <Label for="rule-set-file">Rule set file</Label><Input
          id="rule-set-file"
          type="file"
          accept="application/json,.json"
          onchange={read}
        />
      </div>
      {#if file}<div class="field-group">
          <Label for="rule-set-import-name">Name</Label><Input
            id="rule-set-import-name"
            bind:value={name}
            maxlength={128}
            required
          />
          <p class="field-help muted">
            {file.rules.length}
            {file.rules.length === 1 ? "rule" : "rules"}
          </p>
        </div>{/if}
      {#if error}<p class="field-error" role="alert">{error}</p>{/if}
      <Dialog.Footer
        ><Button
          variant="ghost"
          type="button"
          disabled={busy}
          onclick={() => (open = false)}>Cancel</Button
        ><Button type="submit" disabled={busy || !file || !name.trim()}
          >{busy ? "Importing…" : "Import"}</Button
        ></Dialog.Footer
      >
    </form>
  </Dialog.Content>
</Dialog.Root>
