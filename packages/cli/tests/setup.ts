import { ALL_LANGUAGES, loadGrammars } from '../src/analysis/parser';

// Parsing is synchronous, but loading a grammar isn't: rules called directly need them ready.
await loadGrammars(ALL_LANGUAGES);
