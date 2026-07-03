import React, { useState, useEffect } from "react";
import { ArrowRight, Check } from "lucide-react";
import watsonLogo from "../assets/watson-logo.png";

const SHERLOCK_QUOTES = [
  '"It is a capital mistake to theorize before one has data."',
  '"The world is full of obvious things which nobody by any chance ever observes."',
  '"There is nothing more deceptive than an obvious fact."',
  '"You see, but you do not observe."',
  '"Data! Data! Data! I can\'t make bricks without clay."',
  '"When you have eliminated the impossible, whatever remains, however improbable, must be the truth."',
  '"The little things are infinitely the most important."',
  '"What one man can invent, another can discover."',
];

const getRandomQuote = () => SHERLOCK_QUOTES[Math.floor(Math.random() * SHERLOCK_QUOTES.length)];

interface WelcomeOverlayProps {
  onComplete: () => void;
}

const STEPS = [
  {
    title: "Investigate Anything",
    body: "Type a person, company, domain, email, crypto wallet, or research topic. Watson investigates autonomously across 7 phases — surface collection, identifier pivoting, deep investigation, cross-referencing, synthesis, and report.",
  },
  {
    title: "Connect the Dots",
    body: "Findings flow into the Case Board and Evidence Map automatically. Select two findings on the Case Board and click \"Deep Investigate\" to explore hidden connections between them.",
  },
  {
    title: "Personnel Dossiers",
    body: "When Watson identifies notable people or organizations in an investigation, they automatically appear in the Personnel tab. You can also add suspects manually.",
  },
  {
    title: "Evidence-Backed",
    body: "Every finding carries a source URL and confidence score. Watson never fabricates data. Verifiability scores tell you how solid the evidence is — aim for 70%+.",
  },
];

export default function WelcomeOverlay({ onComplete }: WelcomeOverlayProps) {
  const [step, setStep] = useState(0);
  const [visible, setVisible] = useState(false);

  useEffect(() => {
    // Small delay for entrance animation
    const t = setTimeout(() => setVisible(true), 200);
    return () => clearTimeout(t);
  }, []);

  const current = STEPS[step];
  const isLast = step === STEPS.length - 1;
  const [quote] = useState(getRandomQuote);

  return (
    <div
      className={`fixed inset-0 z-50 bg-black/90 flex items-center justify-center p-4 transition-opacity duration-500 ${
        visible ? "opacity-100" : "opacity-0"
      }`}
    >
      <div className="bg-surface-container border border-outline-variant max-w-lg w-full rounded-xl shadow-2xl overflow-hidden">
        {/* Progress bar */}
        <div className="h-1 bg-surface-container-highest">
          <div
            className="h-full bg-primary transition-all duration-500 ease-out"
            style={{ width: `${((step + 1) / STEPS.length) * 100}%` }}
          />
        </div>

        {/* Content */}
        <div className="p-8 text-center space-y-5">
          <div className="mx-auto w-24 h-24 rounded-xl flex items-center justify-center overflow-hidden">
            <img src={watsonLogo} alt="Watson" className="w-full h-full object-contain" />
          </div>

          {step === 0 && (
            <p className="text-amber-400/80 italic text-sm font-serif leading-relaxed px-2">
              {quote}
            </p>
          )}

          <div>
            <h2 className="font-headline-md text-primary text-xl font-bold mb-2">
              {current.title}
            </h2>
            <p className="font-body-sm text-sm text-on-surface-variant leading-relaxed">
              {current.body}
            </p>
          </div>
        </div>

        {/* Footer */}
        <div className="px-8 pb-6 flex items-center justify-between">
          {/* Step dots */}
          <div className="flex gap-1.5">
            {STEPS.map((_, i) => (
              <div
                key={i}
                className={`w-2 h-2 rounded-full transition-colors ${
                  i <= step ? "bg-primary" : "bg-outline-variant/40"
                }`}
              />
            ))}
          </div>

          <div className="flex gap-2">
            {step > 0 && (
              <button
                onClick={() => setStep(step - 1)}
                className="px-4 py-2 text-xs font-label-caps text-on-surface-variant hover:text-primary transition-colors cursor-pointer"
              >
                Back
              </button>
            )}
            <button
              onClick={isLast ? onComplete : () => setStep(step + 1)}
              className="px-5 py-2 bg-primary text-background-dark font-label-caps font-bold rounded-lg hover:brightness-110 transition-all text-xs flex items-center gap-2 cursor-pointer"
            >
              {isLast ? (
                <>
                  <Check size={14} />
                  Get Started
                </>
              ) : (
                <>
                  Next
                  <ArrowRight size={14} />
                </>
              )}
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}
