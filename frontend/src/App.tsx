import React from "react";
import Sidebar from "./components/Sidebar";
import CaseBoard from "./components/CaseBoard";
import InvestigationMap from "./components/InvestigationMap";
import OSINTToolkit from "./components/OSINTToolkit";
import ArchiveList from "./components/ArchiveList";
import Personnel from "./components/Personnel";
import WatsonChat from "./components/WatsonChat";
import SettingsModal from "./components/SettingsModal";
import WelcomeOverlay from "./components/WelcomeOverlay";
import { Menu, X, Settings, MessageSquare } from "lucide-react";
import { WatsonStoreProvider, useWatsonStore } from "./store/WatsonStore";

function AppInner() {
  const {
    state,
    dispatch,
    handleFindings,
    handleBriefEntities,
    handleConnectClues,
    handleToggleTwin,
    handleTwinInvestigate,
    handleDeleteClue,
    handleAddSuspect,
  } = useWatsonStore();

  const [currentTab, setCurrentTab] = React.useState<string>("chat");
  const [mobileMenuOpen, setMobileMenuOpen] = React.useState(false);
  const [showWelcome, setShowWelcome] = React.useState(() => {
    return !localStorage.getItem("WATSON_ONBOARDED");
  });

  // Auto-switch to chat when twin investigation fires
  React.useEffect(() => {
    if (state.twinQuery) setCurrentTab("chat");
  }, [state.twinQuery]);

  const renderActiveTab = () => {
    switch (currentTab) {
      case "board":
        return (
          <CaseBoard
            clues={state.clues}
            onAddClue={(clue) => dispatch({ type: "ADD_CLUE", clue })}
            onDeleteClue={handleDeleteClue}
            onConnectClues={handleConnectClues}
            selectedForTwin={state.selectedForTwin}
            onToggleTwin={handleToggleTwin}
            onTwinInvestigate={handleTwinInvestigate}
            twinLoading={state.twinLoading}
            twinResult={state.twinResult}
          />
        );
      case "map":
        return (
          <InvestigationMap
            clues={state.clues}
            suspects={state.suspects}
            onAddClue={(clue) => dispatch({ type: "ADD_CLUE", clue })}
            onDeleteClue={handleDeleteClue}
            deductionProbability={state.deductionProbability}
          />
        );
      case "osint":
        return <ArchiveList />;
      case "personnel":
        return (
          <Personnel
            suspects={state.suspects}
            onAddSuspect={handleAddSuspect}
          />
        );
      case "chat":
        return (
          <WatsonChat
            onFindings={handleFindings}
            onBriefEntities={handleBriefEntities}
            twinQuery={state.twinQuery}
            onTwinComplete={() => dispatch({ type: "SET_TWIN_QUERY", query: null })}
          />
        );
      default:
        return (
          <WatsonChat
            onFindings={handleFindings}
            onBriefEntities={handleBriefEntities}
            twinQuery={state.twinQuery}
            onTwinComplete={() => dispatch({ type: "SET_TWIN_QUERY", query: null })}
          />
        );
    }
  };

  const tabs = [
    { id: "chat", label: "Investigate" },
    { id: "board", label: "Case Board" },
    { id: "map", label: "Evidence Map" },
    { id: "osint", label: "Archives" },
    { id: "personnel", label: "Personnel" },
  ];

  return (
    <div className="bg-background-dark text-on-surface font-body-md min-h-screen relative overflow-x-hidden">
      {/* Header */}
      <header className="fixed top-0 w-full z-50 bg-surface-container border-b border-outline-variant/60 flex justify-between items-center px-6 py-4 lg:px-8">
        <div className="flex items-center gap-3">
          <button
            onClick={() => setMobileMenuOpen(!mobileMenuOpen)}
            className="lg:hidden text-primary hover:opacity-80 cursor-pointer"
          >
            {mobileMenuOpen ? <X size={20} /> : <Menu size={20} />}
          </button>
          <div className="font-headline-md text-primary tracking-tight font-bold text-xl lg:text-2xl">
            Watson
          </div>
        </div>
        <nav className="hidden md:flex items-center gap-8 font-label-caps text-xs">
          {tabs.map((tab) => (
            <button
              key={tab.id}
              onClick={() => setCurrentTab(tab.id)}
              className={`cursor-pointer transition-colors pb-1 ${
                currentTab === tab.id
                  ? "text-primary border-b-2 border-primary"
                  : "text-on-surface-variant hover:text-primary"
              }`}
            >
              {tab.label}
            </button>
          ))}
        </nav>
        <div className="flex items-center gap-4">
          <button
            onClick={() => setCurrentTab("chat")}
            className="text-primary hover:opacity-80 transition-opacity cursor-pointer"
          >
            <MessageSquare size={18} className="animate-pulse" />
          </button>
          <button
            onClick={() => dispatch({ type: "SET_SETTINGS_OPEN", open: true })}
            className="text-primary hover:opacity-80 transition-opacity cursor-pointer"
          >
            <Settings size={18} />
          </button>
        </div>
      </header>

      {/* Mobile nav */}
      {mobileMenuOpen && (
        <div className="fixed inset-0 bg-black/95 z-40 pt-24 px-6 flex flex-col space-y-4 lg:hidden">
          {tabs.map((tab) => (
            <button
              key={tab.id}
              onClick={() => {
                setCurrentTab(tab.id);
                setMobileMenuOpen(false);
              }}
              className="text-left py-3 text-lg border-b border-outline-variant/40 font-headline-md text-primary"
            >
              {tab.label}
            </button>
          ))}
        </div>
      )}

      <Sidebar
        currentTab={currentTab}
        setCurrentTab={setCurrentTab}
        deductionProbability={state.deductionProbability}
        onOpenSettings={() => dispatch({ type: "SET_SETTINGS_OPEN", open: true })}
      />

      <main className="lg:ml-64 pt-20 min-h-screen relative bg-background-dark select-none">
        {renderActiveTab()}
      </main>

      {state.settingsOpen && (
        <SettingsModal
          isOpen={state.settingsOpen}
          onClose={() => dispatch({ type: "SET_SETTINGS_OPEN", open: false })}
        />
      )}

      {showWelcome && (
        <WelcomeOverlay
          onComplete={() => {
            localStorage.setItem("WATSON_ONBOARDED", "true");
            setShowWelcome(false);
          }}
        />
      )}
    </div>
  );
}

export default function App() {
  return (
    <WatsonStoreProvider>
      <AppInner />
    </WatsonStoreProvider>
  );
}
