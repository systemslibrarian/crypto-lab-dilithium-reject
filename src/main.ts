import './style.css';

document.querySelector<HTMLDivElement>('#app')!.innerHTML = `
  <main class="shell">
    <section class="hero">
      <p class="eyebrow">ML-DSA Rejection Sampling Explorer</p>
      <h1>Fiat-Shamir with Aborts, made visible.</h1>
      <p class="lede">
        Phase 0 scaffold is in place. The rejection-loop visualizer and ML-DSA instrumentation
        will be layered on top of this shell next.
      </p>
    </section>
  </main>
`;
