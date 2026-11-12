<script lang="ts">
  // A built-in value, boxed so it stands apart from names people enter.
  let { kind }: { kind: "any" | "gateway" } = $props();
</script>

<span class="built-in-value">{kind === "any" ? "Any" : "Gateway"}</span>
