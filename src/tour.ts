/**
 * Guided tour with self-check quizzes. Generic over a list of steps: each step
 * highlights a target section, shows narrative, and can offer an action button
 * (e.g. "Sign one now") and a multiple-choice question with feedback.
 *
 * Non-modal by design: the page stays fully interactive so learners can play
 * with the exhibit a step is pointing at. Keyboard: Esc exits, the panel's
 * buttons handle the rest; the heading receives focus on each step change so
 * screen readers announce progress.
 */

export interface TourQuiz {
  question: string;
  options: string[];
  /** Index into `options`. */
  answer: number;
  explain: string;
}

export interface TourStep {
  /** CSS selector of the section to highlight and scroll to. */
  target: string;
  title: string;
  /** Trusted HTML (authored in-repo, never user input). */
  body: string;
  action?: { label: string; run: () => void };
  quiz?: TourQuiz;
}

const HIGHLIGHT_CLASS = 'tour-highlight';

function prefersReducedMotion(): boolean {
  return window.matchMedia?.('(prefers-reduced-motion: reduce)').matches ?? false;
}

export interface TourController {
  start: () => void;
  stop: () => void;
  isActive: () => boolean;
}

export function createTour(steps: TourStep[]): TourController {
  let panel: HTMLDivElement | null = null;
  let index = 0;
  let highlighted: Element | null = null;

  function clearHighlight(): void {
    highlighted?.classList.remove(HIGHLIGHT_CLASS);
    highlighted = null;
  }

  function stop(): void {
    clearHighlight();
    panel?.remove();
    panel = null;
    document.removeEventListener('keydown', onKeydown);
  }

  function onKeydown(e: KeyboardEvent): void {
    if (e.key === 'Escape') stop();
  }

  function renderStep(): void {
    if (!panel) return;
    const step = steps[index];
    if (!step) {
      stop();
      return;
    }

    clearHighlight();
    const target = document.querySelector(step.target);
    if (target) {
      target.classList.add(HIGHLIGHT_CLASS);
      highlighted = target;
      target.scrollIntoView({ behavior: prefersReducedMotion() ? 'auto' : 'smooth', block: 'start' });
    }

    const quiz = step.quiz;
    panel.innerHTML = `
      <div class="tour-head">
        <h2 class="tour-title" tabindex="-1">${step.title}</h2>
        <span class="tour-progress">${index + 1} / ${steps.length}</span>
      </div>
      <div class="tour-body">${step.body}</div>
      ${step.action ? `<button type="button" class="tour-action">${step.action.label}</button>` : ''}
      ${
        quiz
          ? `<fieldset class="tour-quiz">
               <legend>${quiz.question}</legend>
               <div class="tour-quiz-options">
                 ${quiz.options.map((opt, i) => `<button type="button" class="tour-quiz-option" data-idx="${i}">${opt}</button>`).join('')}
               </div>
               <p class="tour-quiz-feedback" role="status" aria-live="polite"></p>
             </fieldset>`
          : ''
      }
      <div class="tour-nav">
        <button type="button" class="tour-prev" ${index === 0 ? 'disabled' : ''}>◀ Back</button>
        <button type="button" class="tour-next">${index === steps.length - 1 ? 'Finish' : 'Next ▶'}</button>
        <button type="button" class="tour-exit">Exit tour</button>
      </div>
    `;

    panel.querySelector('.tour-prev')?.addEventListener('click', () => {
      index = Math.max(0, index - 1);
      renderStep();
    });
    panel.querySelector('.tour-next')?.addEventListener('click', () => {
      if (index >= steps.length - 1) stop();
      else {
        index += 1;
        renderStep();
      }
    });
    panel.querySelector('.tour-exit')?.addEventListener('click', stop);
    const actionBtn = panel.querySelector('.tour-action');
    if (actionBtn && step.action) actionBtn.addEventListener('click', step.action.run);

    if (quiz) {
      const feedback = panel.querySelector<HTMLParagraphElement>('.tour-quiz-feedback');
      panel.querySelectorAll<HTMLButtonElement>('.tour-quiz-option').forEach((btn) => {
        btn.addEventListener('click', () => {
          const chosen = Number(btn.dataset.idx);
          const correct = chosen === quiz.answer;
          panel?.querySelectorAll<HTMLButtonElement>('.tour-quiz-option').forEach((b) => {
            b.classList.toggle('quiz-correct', Number(b.dataset.idx) === quiz.answer);
            b.classList.toggle('quiz-incorrect', b === btn && !correct);
          });
          if (feedback) {
            feedback.textContent = correct ? `Correct — ${quiz.explain}` : `Not quite. ${quiz.explain}`;
            feedback.className = `tour-quiz-feedback ${correct ? 'ok' : 'bad'}`;
          }
        });
      });
    }

    panel.querySelector<HTMLHeadingElement>('.tour-title')?.focus();
  }

  function start(): void {
    if (panel) {
      index = 0;
      renderStep();
      return;
    }
    index = 0;
    panel = document.createElement('div');
    panel.className = 'tour-panel';
    panel.setAttribute('role', 'dialog');
    panel.setAttribute('aria-label', 'Guided tour');
    document.body.append(panel);
    document.addEventListener('keydown', onKeydown);
    renderStep();
  }

  return { start, stop, isActive: () => panel !== null };
}
