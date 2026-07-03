import React from "react";
import { CaseDeduction } from "../types";
import { 
  FileCheck, 
  User, 
  Compass, 
  Activity, 
  Flame, 
  Printer, 
  RotateCw, 
  MapPin,
  Sparkles,
  Award
} from "lucide-react";

interface DeductionEngineProps {
  deduction: CaseDeduction | null;
  loading: boolean;
  onDeduce: () => void;
  onClose: () => void;
}

export default function DeductionEngine({ 
  deduction, 
  loading, 
  onDeduce, 
  onClose 
}: DeductionEngineProps) {

  const handlePrint = () => {
    window.print();
  };

  return (
    <div className="fixed inset-0 bg-black/90 z-50 flex items-center justify-center p-4 lg:p-8 select-text">
      <div className="bg-surface-container border border-outline-variant max-w-4xl w-full h-[90vh] rounded shadow-2xl flex flex-col overflow-hidden">
        {/* Header bar */}
        <div className="border-b border-outline-variant p-5 flex justify-between items-center bg-surface-container-low">
          <div className="flex items-center gap-3">
            <Award className="text-primary" size={24} />
            <div>
              <h2 className="font-headline-md text-primary text-xl lg:text-2xl font-bold">Holmes-Watson Deduction Engine</h2>
              <p className="font-technical text-[9px] text-on-surface-variant uppercase tracking-widest mt-0.5">
                AI Synthesis of Ledger Coordinates &amp; Crimson Twine
              </p>
            </div>
          </div>
          <div className="flex gap-2">
            {deduction && (
              <button
                onClick={handlePrint}
                className="px-3 py-1.5 text-xs font-label-caps border border-outline-variant text-on-surface-variant hover:text-on-surface hover:bg-surface-container-high rounded flex items-center gap-1.5 cursor-pointer"
              >
                <Printer size={13} />
                <span>Print Ledger</span>
              </button>
            )}
            <button
              onClick={onClose}
              className="px-3.5 py-1.5 text-xs font-label-caps bg-surface-container-highest border border-outline-variant text-primary hover:brightness-110 rounded cursor-pointer"
            >
              Back to Desk
            </button>
          </div>
        </div>

        {/* Content Section */}
        <div className="flex-1 overflow-y-auto p-6 bg-surface-dark space-y-6">
          {loading ? (
            <div className="h-full flex flex-col items-center justify-center text-center py-16 space-y-4">
              <RotateCw className="animate-spin text-primary" size={40} />
              <div className="space-y-1">
                <h3 className="font-headline-md text-primary text-lg">Synthesizing Crime Layout</h3>
                <p className="font-body-sm text-xs text-on-surface-variant italic max-w-md">
                  Analyzing coordinates, linking suspect bios, scraping email metadata, and parsing anonymous warnings to draft the definitive solution ledger...
                </p>
              </div>
            </div>
          ) : deduction ? (
            <div className="space-y-8 animate-fade-in print:bg-white print:text-black">
              {/* Core Verdict Panel */}
              <div className="tactile-paper-light p-6 rounded shadow-xl grid grid-cols-1 md:grid-cols-12 gap-6 items-center relative border-2 border-primary/50">
                {/* Vintage Seal Stamp */}
                <div className="absolute top-2 right-2 border-2 border-red-800/80 rounded-full w-12 h-12 flex items-center justify-center text-red-800/80 font-bold text-[9px] uppercase tracking-widest rotate-12 select-none font-technical">
                  SOLVED
                </div>

                <div className="md:col-span-8 space-y-2">
                  <div className="font-technical text-[9px] tracking-widest text-secondary-container font-bold uppercase">
                    Calculated Primary Perpetrator
                  </div>
                  <h3 className="font-headline-lg text-3xl lg:text-4xl text-secondary-container leading-none font-bold">
                    {deduction.culprit}
                  </h3>
                  <p className="font-body-sm text-xs text-on-surface-variant leading-relaxed">
                    Based on connected telegram footprints, metadata traces, and geological analysis of the Grimpen Mire, Jack Stapleton is identified as the chief conspirator.
                  </p>
                </div>

                <div className="md:col-span-4 flex flex-col items-center text-center border-t md:border-t-0 md:border-l border-outline/30 pt-4 md:pt-0">
                  <span className="font-label-caps text-[10px] text-on-surface-variant uppercase mb-1">
                    CONFIDENCE SCALE
                  </span>
                  <div className="font-technical text-5xl font-bold text-secondary-container">
                    {deduction.probability}%
                  </div>
                  <span className="font-body-sm text-[10px] text-on-surface-variant/70 italic mt-1 uppercase">
                    Forensic Proof Locked
                  </span>
                </div>
              </div>

              {/* Motive & Modus Operandi columns */}
              <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                {/* Motive Card */}
                <div className="tactile-paper p-5 border border-outline-variant space-y-3 shadow-lg transform -rotate-0.5">
                  <div className="font-label-caps text-primary text-xs border-b border-outline-variant/40 pb-1.5 flex items-center gap-1.5 uppercase">
                    <Flame size={14} />
                    <span>The Criminal Motive</span>
                  </div>
                  <p className="font-body-sm text-xs leading-relaxed text-on-surface-variant text-justify">
                    {deduction.motive}
                  </p>
                </div>

                {/* Method / Modus Operandi Card */}
                <div className="tactile-paper p-5 border border-outline-variant space-y-3 shadow-lg transform rotate-0.5">
                  <div className="font-label-caps text-primary text-xs border-b border-outline-variant/40 pb-1.5 flex items-center gap-1.5 uppercase">
                    <Compass size={14} />
                    <span>The Modus Operandi (Method)</span>
                  </div>
                  <p className="font-body-sm text-xs leading-relaxed text-on-surface-variant text-justify">
                    {deduction.method}
                  </p>
                </div>
              </div>

              {/* Master Narrative Summary */}
              <div className="tactile-paper p-6 border border-outline-variant space-y-3 shadow-lg">
                <div className="font-label-caps text-primary text-xs border-b border-outline-variant/40 pb-2 flex items-center gap-1.5 uppercase tracking-wider">
                  <Sparkles size={14} />
                  <span>Watson's Forensic Narrative Summary</span>
                </div>
                <div className="font-body-sm text-[13px] leading-relaxed text-on-surface text-justify italic whitespace-pre-line first-letter:text-3xl first-letter:font-headline-lg first-letter:text-primary first-letter:mr-2 first-letter:float-left">
                  {deduction.summary}
                </div>
              </div>

              {/* Vertical Timeline of Conspiracy */}
              <div className="space-y-4">
                <div className="font-label-caps text-primary text-xs uppercase tracking-wider flex items-center gap-2 border-b border-outline-variant/40 pb-2">
                  <Activity size={14} />
                  <span>Timeline of the Baskerville Conspiracy</span>
                </div>
                
                <div className="relative pl-6 border-l border-outline-variant/50 space-y-6 ml-2">
                  {deduction.timeline.map((event, idx) => (
                    <div key={idx} className="relative space-y-1">
                      {/* Timeline dot */}
                      <div className="absolute -left-[30px] top-1 w-3.5 h-3.5 rounded-full bg-primary border-2 border-background-dark flex items-center justify-center">
                        <div className="w-1 h-1 bg-background-dark rounded-full" />
                      </div>

                      <div className="flex flex-wrap items-center gap-x-3 gap-y-1">
                        <span className="font-technical text-[10px] bg-primary/10 border border-primary/20 text-primary px-2 py-0.5 rounded uppercase font-bold">
                          {event.date}
                        </span>
                        <h4 className="font-headline-md text-sm text-on-surface font-bold">
                          {event.event}
                        </h4>
                      </div>
                      
                      <p className="font-body-sm text-xs text-on-surface-variant leading-relaxed text-justify">
                        {event.relevance}
                      </p>
                    </div>
                  ))}
                </div>
              </div>

              {/* Footer Stamp */}
              <div className="text-center py-6 text-on-surface-variant/40 text-[10px] font-technical uppercase tracking-widest border-t border-outline-variant/20">
                WATSON DEDUCTION LEDGER NO. 221B // LONDON RECORD STAMP
              </div>
            </div>
          ) : (
            <div className="h-full flex flex-col items-center justify-center text-center py-16 space-y-4 shadow-inner">
              <FileCheck size={48} className="text-on-surface-variant/30 animate-pulse" />
              <div className="space-y-1">
                <h3 className="font-headline-md text-primary text-lg">Solution Engine Idle</h3>
                <p className="font-body-sm text-xs text-on-surface-variant italic max-w-sm">
                  Click "Generate Master Deduction" to trigger Dr. Watson's AI framework. It will analyze your board coordinates, suspects, and threat logs.
                </p>
                <div className="pt-4">
                  <button
                    onClick={onDeduce}
                    className="px-6 py-2.5 bg-primary text-background-dark font-label-caps rounded font-bold hover:brightness-110 active:scale-95 cursor-pointer transition-all uppercase text-xs"
                  >
                    Generate Master Deduction
                  </button>
                </div>
              </div>
            </div>
          )}
        </div>

        {/* Action footer bar */}
        <div className="p-4 border-t border-outline-variant bg-surface-container-low flex justify-between items-center">
          <div className="text-[10px] font-technical text-on-surface-variant/50">
            {deduction ? "SOLUTION LOCKED IN LOCAL LEDGER" : "PENDING SYSTHESIS"}
          </div>
          {deduction && (
            <button
              onClick={onDeduce}
              className="px-4 py-2 text-xs font-label-caps bg-primary text-background-dark font-bold hover:brightness-110 rounded flex items-center gap-2 cursor-pointer"
            >
              <RotateCw size={12} />
              <span>Re-Deduce Case</span>
            </button>
          )}
        </div>
      </div>
    </div>
  );
}
