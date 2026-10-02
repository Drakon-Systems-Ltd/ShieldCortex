/**
 * Multilingual injection floor (issue #506).
 *
 * A closed phrase table for the small set of explicit injection imperatives
 * that survive translation: ignore-previous-instructions, new-instructions,
 * role hijack ("you are now"), and system-prompt reveal. Ten languages, the
 * ones seen in the 15 Sep adversarial run plus the common set. This is a
 * phrase list, not a detector of intent: a reworded attack in any language
 * still passes, and that is the stated limit of a regex tier.
 *
 * Every entry is a full imperative phrase, not a bare word, so ordinary
 * foreign-language prose ("the instructions are in the manual") does not hit.
 */

export interface MultilingualPhrase {
  /** BCP-47-ish tag, for evidence only. */
  lang: string;
  pattern: RegExp;
}

export const MULTILINGUAL_INJECTION_PHRASES: MultilingualPhrase[] = [
  // French
  { lang: 'fr', pattern: /ignor(?:e|ez)\s+(?:toutes\s+)?(?:les\s+)?instructions?\s+pr[ée]c[ée]dentes/i },
  { lang: 'fr', pattern: /nouvelles?\s+instructions?\s*:/i },
  { lang: 'fr', pattern: /tu\s+es\s+(?:d[ée]sormais|maintenant)\s+un/i },
  { lang: 'fr', pattern: /r[ée]v[èe]le\s+(?:ton|votre)\s+prompt\s+syst[èe]me/i },
  // Spanish
  { lang: 'es', pattern: /ignor[ae]\s+(?:todas\s+)?(?:las\s+)?instrucciones?\s+anteriores/i },
  { lang: 'es', pattern: /nuevas?\s+instrucciones?\s*:/i },
  { lang: 'es', pattern: /ahora\s+eres\s+un/i },
  { lang: 'es', pattern: /revela\s+tu\s+prompt\s+del\s+sistema/i },
  // German
  { lang: 'de', pattern: /ignoriere\s+(?:alle\s+)?(?:vorherigen|bisherigen)\s+anweisungen/i },
  { lang: 'de', pattern: /neue\s+anweisungen\s*:/i },
  { lang: 'de', pattern: /du\s+bist\s+(?:jetzt|nun)\s+ein/i },
  { lang: 'de', pattern: /zeige\s+(?:mir\s+)?dein(?:en)?\s+system-?prompt/i },
  // Portuguese
  { lang: 'pt', pattern: /ignor[ae]\s+(?:todas\s+)?(?:as\s+)?instru[çc][õo]es\s+anteriores/i },
  { lang: 'pt', pattern: /novas?\s+instru[çc][õo]es\s*:/i },
  { lang: 'pt', pattern: /agora\s+voc[êe]\s+[ée]\s+um/i },
  { lang: 'pt', pattern: /revele\s+seu\s+prompt\s+de\s+sistema/i },
  // Russian
  { lang: 'ru', pattern: /игнорируй(?:те)?\s+(?:все\s+)?предыдущие\s+инструкции/i },
  { lang: 'ru', pattern: /новые\s+инструкции\s*:/i },
  { lang: 'ru', pattern: /теперь\s+ты\s+/i },
  { lang: 'ru', pattern: /покажи\s+(?:свой\s+)?системный\s+промпт/i },
  // Chinese (simplified)
  { lang: 'zh', pattern: /忽略(?:之前|以前|先前)的?(?:所有)?指令/ },
  { lang: 'zh', pattern: /新的?指令[：:]/ },
  { lang: 'zh', pattern: /你现在是/ },
  { lang: 'zh', pattern: /显示你的系统提示/ },
  // Japanese
  { lang: 'ja', pattern: /(?:以前|前)の(?:すべての)?指示を無視/ },
  { lang: 'ja', pattern: /新しい指示[：:]/ },
  { lang: 'ja', pattern: /あなたは今(?:から)?/ },
  { lang: 'ja', pattern: /システムプロンプトを(?:表示|出力)/ },
  // Korean
  { lang: 'ko', pattern: /이전\s?지시(?:를|사항)?\s?무시/ },
  { lang: 'ko', pattern: /새로운\s?지시[：:]/ },
  { lang: 'ko', pattern: /너는\s?이제/ },
  { lang: 'ko', pattern: /시스템\s?프롬프트를\s?(?:보여|출력)/ },
  // Arabic
  { lang: 'ar', pattern: /تجاهل\s+(?:جميع\s+)?التعليمات\s+السابقة/ },
  { lang: 'ar', pattern: /تعليمات\s+جديدة\s*:/ },
  { lang: 'ar', pattern: /أنت\s+الآن/ },
  { lang: 'ar', pattern: /أظهر\s+موجه\s+النظام/ },
  // Hindi
  { lang: 'hi', pattern: /पिछले\s+निर्देशों?\s+को\s+अनदेखा/ },
  { lang: 'hi', pattern: /नए\s+निर्देश\s*:/ },
  { lang: 'hi', pattern: /अब\s+तुम/ },
  { lang: 'hi', pattern: /अपना\s+सिस्टम\s+प्रॉम्प्ट\s+दिखाओ/ },
];

/** First matching language tag, or null. */
export function detectMultilingualInjection(content: string): string | null {
  for (const entry of MULTILINGUAL_INJECTION_PHRASES) {
    if (entry.pattern.test(content)) return entry.lang;
  }
  return null;
}
