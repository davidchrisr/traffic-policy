<script lang="ts">
  let { size = 20 }: { size?: number } = $props();
</script>

<svg
  class="block shrink-0"
  width={size}
  height={size}
  viewBox="0 0 24 24"
  fill="none"
  stroke="currentColor"
  stroke-width="2.5"
  stroke-linecap="round"
  stroke-linejoin="round"
  aria-hidden="true"
  ><path
    d="M2 12h5M7 12c3 0 4-5 7-5h7M18 4l3 3-3 3M7 12c3 0 4 5 7 5h1M18 14v6"
  /></svg
>
