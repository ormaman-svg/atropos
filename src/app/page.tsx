import { Mark } from "@/components/mark";

/*
 * Scaffold placeholder. Exists to prove the token pipeline and the self-hosted
 * fonts render before the console port lands on top of it.
 */
export default function Home() {
  return (
    <main className="flex min-h-screen flex-col items-center justify-center gap-6 bg-paper">
      <div className="flex items-center gap-3">
        <Mark size={38} />
        <h1 className="text-[19px] font-bold tracking-[0.10em] text-ink uppercase">
          Atropos
        </h1>
      </div>
      <p className="max-w-md text-center text-[13px] text-ink-2">
        Agent attack-path analysis. Which agent can reach crown-jewel data, in
        how many hops, and which single fix collapses the most paths.
      </p>
      <p className="font-mono text-[10px] tracking-[0.14em] text-ink-3 uppercase">
        scaffold &middot; step 1
      </p>
    </main>
  );
}
