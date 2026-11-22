// INERT TEST FIXTURE for the Blindspot static scanner.
// Never loaded into a browser; the function below is never called and sends nothing.
// It only contains AI-provider addresses so the scanner can detect them.

const MODELS = {
  openai: 'https://api.openai.com/v1/chat/completions',
  gemini: 'https://generativelanguage.googleapis.com/v1beta/models',
};

function neverCalledSummarise(pageText) {
  return { endpoint: MODELS.openai, length: pageText.length };
}
