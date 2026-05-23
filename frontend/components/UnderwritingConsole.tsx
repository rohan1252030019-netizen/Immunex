import React from 'react';
import { 
  FileText, 
  AlertTriangle, 
  CheckCircle, 
  Eye, 
  HelpCircle, 
  Languages, 
  TrendingUp, 
  ShieldAlert, 
  Clock, 
  UserCheck, 
  Sparkles,
  ChevronRight
} from 'lucide-react';
import { motion, AnimatePresence } from 'framer-motion';

// Mock high-quality demo datasets representing forged and authentic financial deeds
interface DemoDocument {
  id: string;
  name: string;
  type: 'land_record' | 'bank_statement' | 'loan_application';
  originalUrl: string;
  suspiciousUrl: string;
  language: 'English' | 'Hindi' | 'Marathi';
  extractedText: string;
  translation: string;
  forgeryScore: number;
  tamperingConfidence: number;
  underwritingVerdict: 'APPROVE' | 'MANUAL REVIEW' | 'REJECT';
  factors: string[];
  reasoning: string;
  complianceAlerts: string[];
  multilingualOCR: {
    language: string;
    rawText: string;
    translationSummary: string;
    anomaliesFound: string[];
  };
  highlights: Array<{
    id: string;
    box: { top: number; left: number; width: number; height: number };
    issue: string;
    original: string;
    altered: string;
  }>;
}

const DEMO_DATASETS: DemoDocument[] = [
  {
    id: 'DOC-CANARA-401',
    name: 'Canara_Statement_Altered_May_2026.pdf',
    type: 'bank_statement',
    originalUrl: '/original_statement.png',
    suspiciousUrl: '/tampered_statement.png',
    language: 'English',
    extractedText: 'ACCOUNT LEDGER DETAILS -- BALANCE: INR 12,500. MONTHLY SALARY CREDITS: INR 45,000. DEBITS: INR 43,800. ACCOUNT HOLDER: S. KUMAR.',
    translation: 'N/A (Document in English)',
    forgeryScore: 94,
    tamperingConfidence: 96,
    underwritingVerdict: 'REJECT',
    factors: [
      'Altered transaction balances in monthly logs',
      'Metadata inconsistency (Edited with software: PDFExpert)',
      'Direct discrepancy between digit alignment and ledger formatting'
    ],
    reasoning: 'The bank statement PDF is highly suspect. The ending balance of INR 125,203 has been modified to show an inflated value of INR 1,252,030. Bounding box overlay displays systematic pixel manipulation around numerical columns.',
    complianceAlerts: ['RBI-DPS-8.2 (Regulatory Document Verification Failure)', 'FEMA-Sec-11.4 (Fraudulent Account Declarations)'],
    multilingualOCR: {
      language: 'English',
      rawText: 'Statement balance edited under section 4. Final Balance read: INR 1,252,030.',
      translationSummary: 'Standard english statement with anomalous balance figures.',
      anomaliesFound: ['Manipulated numerical strings in transaction columns', 'Metadata modified on 2026-05-23T14:12Z']
    },
    highlights: [
      { id: 'h1', box: { top: 32, left: 60, width: 28, height: 8 }, issue: 'Altered Ending Balance (Modified with mismatching fonts)', original: 'INR 125,203', altered: 'INR 1,252,030' },
      { id: 'h2', box: { top: 68, left: 15, width: 35, height: 6 }, issue: 'Manipulated Metadata (Altered PDF author tools detected)', original: 'Normal PDF Writer', altered: 'PDFEditor-Mac-v12.3' }
    ]
  },
  {
    id: 'DOC-CANARA-402',
    name: 'Regional_Land_Record_Hindi_Forged.pdf',
    type: 'land_record',
    originalUrl: '/original_land.png',
    suspiciousUrl: '/tampered_land.png',
    language: 'Hindi',
    extractedText: 'भूमि अभिलेख प्रलेख -- स्वामी: रामेश सिंह। क्षेत्रफल: २.५ हेक्टेयर। भूखंड संख्या: १२९। Canara Mortgage Assessment Ready.',
    translation: 'LAND DOCUMENTATION LEDGER -- OWNER: Ramesh Singh. LAND AREA: 2.5 Hectares. PLOT NUMBER: 129. Mortgage status active.',
    forgeryScore: 88,
    tamperingConfidence: 91,
    underwritingVerdict: 'REJECT',
    factors: [
      'Multilingual OCR mismatch: Ramesh Singh misspelled in Regional text',
      'Forged land stamp (Sub-registrar signature integrity check failure)',
      'Impossible property dimensions compared to Canara Land Registry DB'
    ],
    reasoning: 'OCR translation mismatch detected. The uploaded Hindi document lists Ramesh Singh as the owner, but database cross-reference indicates plot 129 belongs to Ramesh Kumar. The digital registrar seal is structurally identical to a known forgery signature index.',
    complianceAlerts: ['RBI-DPS-8.4 (Mortgage collateral verification breach)'],
    multilingualOCR: {
      language: 'Hindi (हिंदी)',
      rawText: 'भूमि का क्षेत्रफल २.५ हेक्टेयर है और भूमि का स्वामी रामेश सिंह घोषित किया गया है।',
      translationSummary: 'Land area listed as 2.5 Hectares. Registered owner listed as Ramesh Singh.',
      anomaliesFound: ['Sub-registrar digital stamp verification failed', 'Altered owner spelling in land register']
    },
    highlights: [
      { id: 'h3', box: { top: 45, left: 40, width: 30, height: 10 }, issue: 'Forged Sub-Registrar Stamp (Identity signature spoofing)', original: 'Official Seal #994', altered: 'Spoofed stamp replication' },
      { id: 'h4', box: { top: 15, left: 20, width: 25, height: 7 }, issue: 'Owner Name Discrepancy (OCR Mismatch)', original: 'Ramesh Kumar', altered: 'Ramesh Singh' }
    ]
  },
  {
    id: 'DOC-CANARA-403',
    name: 'Genuine_Loan_Application_Marathi.pdf',
    type: 'loan_application',
    originalUrl: '/genuine_marathi.png',
    suspiciousUrl: '/genuine_marathi.png',
    language: 'Marathi',
    extractedText: 'कर्ज अर्ज विवरण -- अर्जदार: सुनिल भोसले. उत्पन्न: १०,००,००० रुपये. सर्व सुरक्षा पडताळणी पूर्ण.',
    translation: 'LOAN APPLICATION PROFILE -- APPLICANT: Sunil Bhosale. INCOME: INR 1,000,000. All safety verifications passed.',
    forgeryScore: 5,
    tamperingConfidence: 99,
    underwritingVerdict: 'APPROVE',
    factors: [
      'No metadata anomalies found',
      'All structural stamps align with official State registration DB',
      'OCR details completely match the core CRM customer account'
    ],
    reasoning: 'A clean, authentic document profile. Structural signature alignment, OCR translations, and metadata profiles conform exactly to Canara underwriting standards.',
    complianceAlerts: ['RBI-DPS-1.1 (Operational compliance checklist: PASSED)'],
    multilingualOCR: {
      language: 'Marathi (मराठी)',
      rawText: 'अर्जदाराचे एकूण वार्षिक उत्पन्न १०,००,००० रुपये आहे.',
      translationSummary: 'Applicant Sunil Bhosale income declared as INR 1,000,000. Fully aligned.',
      anomaliesFound: []
    },
    highlights: []
  }
];

export default function UnderwritingConsole() {
  const [selectedDoc, setSelectedDoc] = React.useState<DemoDocument>(DEMO_DATASETS[0]);
  const [demoState, setDemoState] = React.useState<'normal' | 'scanning' | 'complete'>('complete');
  const [currentLanguage, setCurrentLanguage] = React.useState<'English' | 'Hindi' | 'Marathi'>('English');

  const handleDocChange = (doc: DemoDocument) => {
    setDemoState('scanning');
    setTimeout(() => {
      setSelectedDoc(doc);
      setCurrentLanguage(doc.language);
      setDemoState('complete');
    }, 1200);
  };

  return (
    <div className="flex-1 flex flex-col overflow-y-auto bg-[#050814] font-mono text-[#cbd5e1] p-6 scrollbar-thin">
      
      {/* Top Impact KPI Metrics Bar */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4 mb-6">
        {[
          { label: 'Underwriting Speed', value: '+84.2%', desc: 'Instant AI Document Triage', icon: TrendingUp, color: 'text-[#00ff88]' },
          { label: 'Forgery Accuracy', value: '99.4%', desc: 'Dynamic signature verification', icon: ShieldAlert, color: 'text-[#00f0ff]' },
          { label: 'Analyst Workload', value: '-72.1%', desc: 'Auto-mapped risk criteria', icon: UserCheck, color: 'text-[#a855f7]' },
          { label: 'RBI Compliance Audit', value: '100%', desc: 'Continuous verification', icon: CheckCircle, color: 'text-[#eab308]' },
        ].map((kpi, idx) => (
          <div key={idx} className="bg-[#0b1028]/80 border border-[#1e2d5a]/60 rounded-2xl p-4 flex items-center justify-between shadow-[0_0_15px_rgba(0,240,255,0.05)] backdrop-blur-md">
            <div>
              <span className="text-[10px] text-[#64748b] tracking-wider block uppercase font-bold">{kpi.label}</span>
              <span className={`text-2xl font-black ${kpi.color} block mt-1`}>{kpi.value}</span>
              <span className="text-[10px] text-[#94a3b8] mt-0.5 block">{kpi.desc}</span>
            </div>
            <div className="p-3 bg-[#131b33] rounded-xl">
              <kpi.icon className={`w-5 h-5 ${kpi.color}`} />
            </div>
          </div>
        ))}
      </div>

      {/* Main Subsystem Grid Layout */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6 items-stretch">
        
        {/* Left Side: Uploads and Demo Datasets */}
        <div className="lg:col-span-4 flex flex-col gap-6">
          
          {/* Document Ingestion list */}
          <div className="bg-[#0a0f24] border border-[#1e2d5a]/60 rounded-3xl p-5 shadow-[0_0_20px_rgba(0,0,0,0.4)] flex flex-col flex-1">
            <h2 className="text-sm font-black tracking-widest text-[#00f0ff] uppercase mb-4 flex items-center gap-2">
              <FileText className="w-4 h-4" /> Underwriting Documents Queue
            </h2>
            <div className="space-y-3 flex-grow">
              {DEMO_DATASETS.map((doc) => {
                const isSelected = selectedDoc.id === doc.id;
                return (
                  <button
                    key={doc.id}
                    onClick={() => handleDocChange(doc)}
                    className={`w-full text-left p-3.5 rounded-xl border transition-all flex flex-col gap-2 relative overflow-hidden ${
                      isSelected
                        ? 'bg-[#131a38] border-[#00f0ff] shadow-[0_0_15px_rgba(0,240,255,0.15)] text-white'
                        : 'bg-[#070c1e] border-[#1e2d5a]/40 hover:border-[#1e2d5a]/80 text-[#94a3b8]'
                    }`}
                  >
                    <div className="flex justify-between items-start">
                      <span className="text-xs font-bold truncate max-w-[190px]">{doc.name}</span>
                      <span className={`text-[9px] px-2 py-0.5 rounded font-black tracking-widest uppercase font-mono ${
                        doc.underwritingVerdict === 'REJECT' ? 'bg-[#ff3366]/10 text-[#ff3366] border border-[#ff3366]/20' : 'bg-[#00ff88]/10 text-[#00ff88] border border-[#00ff88]/20'
                      }`}>
                        {doc.underwritingVerdict}
                      </span>
                    </div>
                    <div className="flex justify-between items-center text-[10px]">
                      <span className="text-[#64748b]">{doc.id}</span>
                      <span className="text-[#00f0ff] font-bold flex items-center gap-1">
                        <Languages className="w-3.5 h-3.5" /> {doc.language}
                      </span>
                    </div>
                  </button>
                );
              })}
            </div>
            
            {/* Live Upload Simulation card */}
            <div className="border border-dashed border-[#1e2d5a]/60 rounded-2xl p-5 mt-4 text-center bg-[#070b1a]/40 hover:bg-[#131a38]/20 transition-all flex flex-col justify-center items-center gap-2 cursor-pointer">
              <Sparkles className="w-7 h-7 text-[#a855f7] animate-pulse" />
              <span className="text-xs font-bold text-white">DRAG & DROP NEW DOCUMENT</span>
              <span className="text-[9px] text-[#64748b]">Supports: regional PDFs, land deeds, bank profiles</span>
            </div>
          </div>
        </div>

        {/* Right Side: Scan details, Side by Side original vs suspicious with visual overlays */}
        <div className="lg:col-span-8 flex flex-col gap-6">
          <div className="bg-[#0a0f24] border border-[#1e2d5a]/60 rounded-3xl p-6 shadow-[0_0_20px_rgba(0,0,0,0.4)] relative flex-1 flex flex-col min-h-[500px]">
            
            {/* Scanned Header */}
            <div className="flex justify-between items-center border-b border-[#1e2d5a]/40 pb-4 mb-4">
              <div>
                <h3 className="text-sm font-extrabold text-white flex items-center gap-2">
                  <Eye className="w-4 h-4 text-[#00f0ff]" /> Live Document Tampering Visualizer
                </h3>
                <span className="text-[10px] text-[#64748b] font-bold tracking-widest block uppercase mt-0.5">
                  ID Mapped: {selectedDoc.id} | Name: {selectedDoc.name}
                </span>
              </div>
              
              <div className="flex gap-2">
                <span className="text-[10px] font-bold tracking-wider px-3 py-1 bg-[#131b35] rounded-lg border border-[#1e2d5a] text-white">
                  Forgery Score: <span className={selectedDoc.forgeryScore > 50 ? 'text-[#ff3366]' : 'text-[#00ff88]'}>{selectedDoc.forgeryScore}%</span>
                </span>
                <span className="text-[10px] font-bold tracking-wider px-3 py-1 bg-[#131b35] rounded-lg border border-[#1e2d5a] text-white">
                  Confidence: <span className="text-[#00f0ff]">{selectedDoc.tamperingConfidence}%</span>
                </span>
              </div>
            </div>

            <AnimatePresence mode="wait">
              {demoState === 'scanning' ? (
                <motion.div 
                  initial={{ opacity: 0 }}
                  animate={{ opacity: 1 }}
                  exit={{ opacity: 0 }}
                  className="flex-grow flex flex-col justify-center items-center gap-3 py-20"
                >
                  <div className="relative w-16 h-16">
                    <div className="absolute inset-0 rounded-full border-4 border-[#00f0ff]/20 border-t-[#00f0ff] animate-spin" />
                  </div>
                  <span className="text-xs font-bold text-[#00f0ff] tracking-widest uppercase animate-pulse">Running Multilingual OCR & Forgery Scanners...</span>
                </motion.div>
              ) : (
                <motion.div 
                  initial={{ opacity: 0 }}
                  animate={{ opacity: 1 }}
                  transition={{ duration: 0.3 }}
                  className="flex-grow flex flex-col gap-6"
                >
                  {/* Grid of original vs suspicious view */}
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                    
                    {/* Authentic Layout simulator */}
                    <div className="bg-[#050814] border border-[#1e2d5a]/40 rounded-2xl p-4 flex flex-col min-h-[220px] relative overflow-hidden">
                      <span className="text-[9px] text-[#00ff88] uppercase tracking-wider font-bold block mb-3 flex items-center gap-1">
                        <CheckCircle className="w-3.5 h-3.5" /> CANARA LEDGER DOCUMENT TEMPLATE (ORIGINAL)
                      </span>
                      
                      {/* Paper simulation */}
                      <div className="flex-grow flex flex-col justify-center p-4 border border-[#1e2d5a]/20 bg-[#070b1a]/80 rounded-xl relative select-none">
                        <div className="w-12 h-1 bg-[#00ff88]/30 rounded mb-4" />
                        <p className="text-[11px] leading-relaxed text-[#64748b] font-serif mb-2">
                          CANARA LOAN ASSESSMENT RECORD. PROOF OF INCOME VERIFIED UNDER SECTION 4. OWNER NAME STATED AS Ramesh Kumar. PLOT AREA REGISTERED: 2.5 HECTARES.
                        </p>
                        <p className="text-[11px] text-[#64748b] leading-relaxed font-serif">
                          STATEMENT ENDING BALANCE: <span className="text-[#00ff88] font-bold">INR 125,203</span>. SIGNATURE DECREED BY OFFICIAL REGISTRAR.
                        </p>
                      </div>
                    </div>

                    {/* Suspect Altered View with red highlighted bounding box overlay */}
                    <div className="bg-[#050814] border border-[#ff3366]/40 rounded-2xl p-4 flex flex-col min-h-[220px] relative overflow-hidden">
                      <span className="text-[9px] text-[#ff3366] uppercase tracking-wider font-bold block mb-3 flex items-center gap-1">
                        <AlertTriangle className="w-3.5 h-3.5 animate-bounce" /> UPLOADED DOCUMENT FORGERY HIGHLIGHT OVERLAY
                      </span>

                      {/* Paper simulation with red bounding box highlights */}
                      <div className="flex-grow flex flex-col justify-center p-4 border border-[#ff3366]/20 bg-[#070b1a]/80 rounded-xl relative">
                        
                        {/* Red overlay highlights */}
                        {selectedDoc.highlights.map((h, i) => (
                          <div
                            key={h.id}
                            className="absolute border border-dashed border-[#ff3366] bg-[#ff3366]/10 rounded shadow-[0_0_8px_rgba(255,51,102,0.4)] cursor-pointer group"
                            style={{
                              top: `${h.box.top}%`,
                              left: `${h.box.left}%`,
                              width: `${h.box.width}%`,
                              height: `${h.box.height}%`,
                            }}
                          >
                            {/* Hover Tooltip showing original vs altered values */}
                            <div className="absolute left-1/2 bottom-full transform -translate-x-1/2 mb-2 w-48 bg-[#0a0f24] border border-[#ff3366]/60 rounded-xl p-2.5 shadow-[0_0_15px_rgba(255,51,102,0.4)] opacity-0 pointer-events-none group-hover:opacity-100 transition-opacity z-50 text-[9px] leading-relaxed">
                              <p className="text-[#ff3366] font-bold uppercase tracking-wider border-b border-[#ff3366]/20 pb-1 mb-1">
                                {h.issue}
                              </p>
                              <p className="text-white">Altered: <span className="text-[#ff3366] font-bold">{h.altered}</span></p>
                              <p className="text-[#64748b]">Should be: <span className="text-[#00ff88] font-bold">{h.original}</span></p>
                            </div>
                          </div>
                        ))}

                        <div className="w-12 h-1 bg-[#ff3366]/30 rounded mb-4" />
                        <p className="text-[11px] leading-relaxed text-[#cbd5e1] font-serif mb-2 select-none">
                          CANARA LOAN ASSESSMENT RECORD. PROOF OF INCOME VERIFIED UNDER SECTION 4. OWNER NAME STATED AS <span className={selectedDoc.language === 'Hindi' ? 'bg-[#ff3366]/20 text-[#ff3366] px-1 rounded border border-[#ff3366]/30' : ''}>Ramesh Singh</span>. PLOT AREA REGISTERED: 2.5 HECTARES.
                        </p>
                        <p className="text-[11px] text-[#cbd5e1] leading-relaxed font-serif select-none">
                          STATEMENT ENDING BALANCE: <span className={selectedDoc.type === 'bank_statement' ? 'bg-[#ff3366]/20 text-[#ff3366] px-1 rounded border border-[#ff3366]/30' : ''}>INR 1,252,030</span>. SIGNATURE DECREED BY OFFICIAL REGISTRAR.
                        </p>
                      </div>
                    </div>
                  </div>

                  {/* Highlights Summary panel */}
                  {selectedDoc.highlights.length > 0 && (
                    <div className="p-4 bg-[#ff3366]/5 border border-[#ff3366]/30 rounded-2xl flex flex-col gap-2">
                      <span className="text-[10px] text-[#ff3366] font-black uppercase tracking-wider flex items-center gap-1.5">
                        <ShieldAlert className="w-4 h-4 animate-pulse" /> Document Forgery Bounding Box Alerts Detected
                      </span>
                      <div className="grid grid-cols-1 md:grid-cols-2 gap-3 text-[10px]">
                        {selectedDoc.highlights.map((h, i) => (
                          <div key={i} className="p-2.5 bg-[#050814]/80 border border-[#ff3366]/20 rounded-xl space-y-1">
                            <p className="text-white font-bold">{h.issue}</p>
                            <div className="flex gap-4">
                              <span>Underwriting File: <span className="text-[#ff3366] font-bold">{h.altered}</span></span>
                              <span className="text-[#64748b]">Original Baseline: <span className="text-[#00ff88] font-bold">{h.original}</span></span>
                            </div>
                          </div>
                        ))}
                      </div>
                    </div>
                  )}

                  {/* Dynamic AI Underwriting recommendation panel */}
                  <div className="grid grid-cols-1 md:grid-cols-3 gap-6 items-stretch">
                    
                    {/* Multi-language OCR Extraction Panel */}
                    <div className="md:col-span-2 bg-[#0b1028]/80 border border-[#1e2d5a]/60 rounded-2xl p-4 flex flex-col justify-between">
                      <div>
                        <div className="flex justify-between items-center border-b border-[#1e2d5a]/40 pb-2 mb-3">
                          <span className="text-xs font-black text-white flex items-center gap-1.5">
                            <Languages className="w-4 h-4 text-[#a855f7]" /> Multilingual OCR Extraction
                          </span>
                          <span className="text-[10px] px-2 py-0.5 bg-[#a855f7]/10 text-[#a855f7] border border-[#a855f7]/20 rounded font-black tracking-widest font-mono uppercase">
                            {selectedDoc.language} DETECTED
                          </span>
                        </div>
                        <div className="space-y-3 text-[10px] leading-relaxed">
                          <div>
                            <span className="text-[#64748b] block font-bold uppercase tracking-wider mb-1">OCR Raw Extracted Segment:</span>
                            <div className="bg-[#050814] p-3 rounded-xl border border-[#1e2d5a]/30 text-white font-serif max-h-[80px] overflow-y-auto scrollbar-thin">
                              {selectedDoc.multilingualOCR.rawText}
                            </div>
                          </div>
                          {selectedDoc.language !== 'English' && (
                            <div>
                              <span className="text-[#64748b] block font-bold uppercase tracking-wider mb-1">Translated Summary (English):</span>
                              <div className="bg-[#050814] p-3 rounded-xl border border-[#1e2d5a]/30 text-[#00f0ff] font-sans">
                                {selectedDoc.translation}
                              </div>
                            </div>
                          )}
                        </div>
                      </div>
                    </div>

                    {/* Underwriting Action Recommendation */}
                    <div className="bg-[#0b1028]/80 border border-[#1e2d5a]/60 rounded-2xl p-4 flex flex-col justify-between relative overflow-hidden">
                      {/* Glow according to decision */}
                      <div className={`absolute top-0 left-0 right-0 h-1 ${
                        selectedDoc.underwritingVerdict === 'REJECT' ? 'bg-[#ff3366]' : 'bg-[#00ff88]'
                      }`} />
                      
                      <div>
                        <span className="text-xs font-black text-white block border-b border-[#1e2d5a]/40 pb-2 mb-3 uppercase tracking-wider">
                          AI Underwriting Verdict
                        </span>
                        
                        <div className="flex items-center gap-3 my-3">
                          <div className={`p-2.5 rounded-xl ${
                            selectedDoc.underwritingVerdict === 'REJECT' ? 'bg-[#ff3366]/10 text-[#ff3366]' : 'bg-[#00ff88]/10 text-[#00ff88]'
                          }`}>
                            {selectedDoc.underwritingVerdict === 'REJECT' ? <ShieldAlert className="w-6 h-6" /> : <UserCheck className="w-6 h-6" />}
                          </div>
                          <div>
                            <span className="text-[10px] text-[#64748b] block uppercase tracking-wider font-bold">RECOMMENDED ACTION</span>
                            <span className={`text-lg font-black tracking-widest ${
                              selectedDoc.underwritingVerdict === 'REJECT' ? 'text-[#ff3366]' : 'text-[#00ff88]'
                            }`}>
                              {selectedDoc.underwritingVerdict}
                            </span>
                          </div>
                        </div>
                        
                        <p className="text-[10px] leading-relaxed text-[#94a3b8]">
                          {selectedDoc.reasoning}
                        </p>
                      </div>

                      <button className={`w-full py-2.5 rounded-xl text-[10px] font-black uppercase tracking-widest mt-4 transition-all hover:scale-[1.01] ${
                        selectedDoc.underwritingVerdict === 'REJECT' 
                          ? 'bg-[#ff3366]/15 hover:bg-[#ff3366]/25 text-[#ff3366] border border-[#ff3366]/20'
                          : 'bg-[#00ff88]/15 hover:bg-[#00ff88]/25 text-[#00ff88] border border-[#00ff88]/20'
                      }`}>
                        EXECUTE {selectedDoc.underwritingVerdict} VERDICT
                      </button>
                    </div>

                  </div>
                </motion.div>
              )}
            </AnimatePresence>

          </div>
        </div>

      </div>

    </div>
  );
}
