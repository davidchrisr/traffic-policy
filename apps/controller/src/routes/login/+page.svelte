<script lang="ts">
  import { enhance } from "$app/forms";
  import type { PageProps } from "./$types";
  import { Button } from "#lib/components/ui/button/index.ts";
  import { Checkbox } from "#lib/components/ui/checkbox/index.ts";
  import { Input } from "#lib/components/ui/input/index.ts";
  import { Label } from "#lib/components/ui/label/index.ts";
  import LogoMark from "#lib/components/LogoMark.svelte";

  let { form }: PageProps = $props();

  let pending = $state(false);
</script>

<svelte:head><title>Sign in · Traffic Policy</title></svelte:head>
<main class="grid min-h-dvh place-items-center px-6">
  <form
    method="POST"
    use:enhance={() => {
      pending = true;
      return async ({ update }) => {
        await update();
        pending = false;
      };
    }}
    class="w-full max-w-sm space-y-6"
  >
    <input
      type="hidden"
      name="username"
      value="Admin"
      autocomplete="username"
    />
    <div>
      <h1 class="page-title flex items-center gap-3">
        <LogoMark size={30} />Traffic Policy
      </h1>
      <p class="muted mt-2">Sign in as Admin to manage network permissions.</p>
    </div>
    <div class="field-group">
      <Label for="password">Password</Label><Input
        id="password"
        type="password"
        name="password"
        autocomplete="current-password"
        required
        aria-invalid={!!form?.message}
        aria-describedby={form?.message ? "login-error" : undefined}
      />
      {#if form?.message}<p id="login-error" class="field-error" role="alert">
          {form.message}
        </p>{/if}
    </div>
    <div class="flex items-center gap-2">
      <Checkbox id="remember" name="remember" /><Label for="remember"
        >Remember me</Label
      >
    </div>
    <Button type="submit" class="w-full" disabled={pending}
      >{pending ? "Signing in…" : "Sign in"}</Button
    >
  </form>
</main>
