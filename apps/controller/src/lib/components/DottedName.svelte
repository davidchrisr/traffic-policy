<script lang="ts">
  // A hostname or address that may wrap after each dot. Each part is keyed by where it starts.
  let { value }: { value: string } = $props();

  const parts = $derived.by(() => {
    let at = 0;

    return value.split(/(?<=\.)/).map((text) => {
      const part = { text, at };
      at += text.length;

      return part;
    });
  });
</script>

{#each parts as part (part.at)}<wbr />{part.text}{/each}
