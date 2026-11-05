import { createSubscriber } from "svelte/reactivity";

// One shared clock for relative times. It ticks only while something on screen reads it.
const subscribe = createSubscriber((update) => {
  const timer = setInterval(update, 15000);

  return () => clearInterval(timer);
});

export function currentTime(): Date {
  subscribe();

  return new Date();
}
