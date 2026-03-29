/**
 * Code Quality and Performance Rules - 120+ Rules
 * Best practices for maintainability, performance, and code smells
 * @module quality-rules
 */

const QUALITY_RULES = {
    // ==================== CODE SMELLS ====================
    CODE_SMELLS: {
        long_function: { severity: 'LOW', impact: 3, cwe: '', message: 'Function exceeds 50 lines - consider splitting' },
        deep_nesting: { severity: 'LOW', impact: 3, cwe: '', message: 'Nesting depth > 4 levels - simplify logic' },
        god_class: { severity: 'MEDIUM', impact: 4, cwe: '', message: 'Class too large (>500 lines) - split responsibilities' },
        long_param_list: { severity: 'LOW', impact: 3, cwe: '', message: 'Function has >5 parameters - use options object' },
        magic_number: { severity: 'LOW', impact: 2, cwe: '', message: 'Magic number - extract to named constant' },
        magic_string: { severity: 'LOW', impact: 2, cwe: '', message: 'Magic string - extract to constant' },
        duplicate_code: { severity: 'MEDIUM', impact: 4, cwe: '', message: 'Duplicate code detected - extract to function' },
        dead_code: { severity: 'LOW', impact: 2, cwe: '', message: 'Dead/unreachable code detected' },
        empty_catch: { severity: 'MEDIUM', impact: 4, cwe: 'CWE-390', message: 'Empty catch block - at minimum log error' },
        ignored_return: { severity: 'LOW', impact: 3, cwe: '', message: 'Return value ignored - intentional?' },
        todo_comment: { severity: 'LOW', impact: 1, cwe: '', message: 'TODO comment should be tracked in issue tracker' },
        fixme_comment: { severity: 'LOW', impact: 2, cwe: '', message: 'FIXME comment indicates known issue' },
        hack_comment: { severity: 'MEDIUM', impact: 3, cwe: '', message: 'HACK comment indicates technical debt' },
    },

    // ==================== COMPLEXITY ====================
    COMPLEXITY: {
        cyclomatic_high: { severity: 'MEDIUM', impact: 4, cwe: '', message: 'High cyclomatic complexity (>10) - simplify' },
        cognitive_high: { severity: 'MEDIUM', impact: 4, cwe: '', message: 'High cognitive complexity - hard to understand' },
        boolean_expr: { severity: 'LOW', impact: 3, cwe: '', message: 'Complex boolean expression - extract to variable' },
        ternary_nested: { severity: 'LOW', impact: 3, cwe: '', message: 'Nested ternary operators - use if/else' },
        switch_fallthrough: { severity: 'MEDIUM', impact: 4, cwe: '', message: 'Switch fallthrough without comment' },
        long_chain: { severity: 'LOW', impact: 3, cwe: '', message: 'Long method chain - consider intermediate variables' },
    },

    // ==================== ERROR HANDLING ====================
    ERROR_HANDLING: {
        no_catch: { severity: 'MEDIUM', impact: 4, cwe: 'CWE-755', message: 'Promise without catch handler' },
        unhandled_async: { severity: 'MEDIUM', impact: 4, cwe: 'CWE-755', message: 'Async function without error handling' },
        throw_string: { severity: 'LOW', impact: 3, cwe: '', message: 'Throwing string instead of Error object' },
        rethrow_generic: { severity: 'MEDIUM', impact: 4, cwe: '', message: 'Catching and rethrowing generic Error' },
        swallowed_error: { severity: 'MEDIUM', impact: 5, cwe: 'CWE-390', message: 'Error caught but not handled' },
        no_finally: { severity: 'LOW', impact: 2, cwe: '', message: 'Try/catch without finally for cleanup' },
    },

    // ==================== PERFORMANCE ====================
    PERFORMANCE: {
        array_in_loop: { severity: 'LOW', impact: 3, cwe: '', message: 'Array creation in loop - move outside' },
        regex_in_loop: { severity: 'MEDIUM', impact: 4, cwe: '', message: 'Regex creation in loop - compile once' },
        string_concat_loop: { severity: 'MEDIUM', impact: 4, cwe: '', message: 'String concatenation in loop - use array.join' },
        console_log: { severity: 'LOW', impact: 2, cwe: '', message: 'console.log in production code' },
        sync_fs: { severity: 'MEDIUM', impact: 5, cwe: '', message: 'Synchronous file operation blocks event loop' },
        no_pagination: { severity: 'MEDIUM', impact: 4, cwe: '', message: 'Query without limit/pagination' },
        n_plus_one: { severity: 'MEDIUM', impact: 5, cwe: '', message: 'Potential N+1 query pattern' },
        unbounded_cache: { severity: 'MEDIUM', impact: 4, cwe: 'CWE-400', message: 'Cache without size limit may exhaust memory' },
        json_parse_loop: { severity: 'MEDIUM', impact: 4, cwe: '', message: 'JSON.parse in loop - consider batching' },
        dom_access_loop: { severity: 'MEDIUM', impact: 4, cwe: '', message: 'DOM access in loop - batch operations' },
        forced_reflow: { severity: 'MEDIUM', impact: 4, cwe: '', message: 'Layout thrashing - batch reads then writes' },
        large_bundle: { severity: 'LOW', impact: 3, cwe: '', message: 'Large import may affect bundle size' },
        no_memoization: { severity: 'LOW', impact: 3, cwe: '', message: 'Heavy computation without memoization' },
        blocking_main: { severity: 'HIGH', impact: 6, cwe: '', message: 'Blocking operation on main thread' },
    },

    // ==================== ASYNC PATTERNS ====================
    ASYNC: {
        callback_hell: { severity: 'MEDIUM', impact: 4, cwe: '', message: 'Nested callbacks - use async/await' },
        await_in_loop: { severity: 'MEDIUM', impact: 4, cwe: '', message: 'Sequential await in loop - use Promise.all' },
        promise_constructor: { severity: 'LOW', impact: 2, cwe: '', message: 'Promise constructor antipattern' },
        race_condition: { severity: 'HIGH', impact: 6, cwe: 'CWE-362', message: 'Potential race condition' },
        missing_await: { severity: 'MEDIUM', impact: 5, cwe: '', message: 'Async function call without await' },
        floating_promise: { severity: 'MEDIUM', impact: 4, cwe: '', message: 'Promise not awaited or chained' },
    },

    // ==================== MEMORY ====================
    MEMORY: {
        event_listener_leak: { severity: 'MEDIUM', impact: 5, cwe: 'CWE-401', message: 'Event listener not removed - memory leak' },
        closure_leak: { severity: 'MEDIUM', impact: 5, cwe: 'CWE-401', message: 'Closure holding reference - potential memory leak' },
        global_state: { severity: 'LOW', impact: 3, cwe: '', message: 'Global mutable state' },
        large_object: { severity: 'LOW', impact: 3, cwe: '', message: 'Large object in memory - consider streaming' },
        timer_leak: { severity: 'MEDIUM', impact: 4, cwe: 'CWE-401', message: 'setInterval not cleared - memory leak' },
    },

    // ==================== TESTING ====================
    TESTING: {
        no_assertions: { severity: 'LOW', impact: 2, cwe: '', message: 'Test without assertions' },
        test_coverage: { severity: 'LOW', impact: 2, cwe: '', message: 'Function not covered by tests' },
        mock_overuse: { severity: 'LOW', impact: 2, cwe: '', message: 'Heavy mocking reduces test value' },
        flaky_test: { severity: 'LOW', impact: 2, cwe: '', message: 'Test depends on external state' },
        disabled_test: { severity: 'LOW', impact: 2, cwe: '', message: 'Skipped/disabled test' },
    },

    // ==================== NAMING ====================
    NAMING: {
        generic_name: { severity: 'LOW', impact: 2, cwe: '', message: 'Generic variable name (data, info, temp)' },
        single_letter: { severity: 'LOW', impact: 2, cwe: '', message: 'Single letter variable outside loop' },
        inconsistent_case: { severity: 'LOW', impact: 2, cwe: '', message: 'Inconsistent naming convention' },
        boolean_prefix: { severity: 'LOW', impact: 1, cwe: '', message: 'Boolean without is/has/should prefix' },
        func_noun: { severity: 'LOW', impact: 1, cwe: '', message: 'Function with noun name should be verb' },
    },

    // ==================== DOCUMENTATION ====================
    DOCUMENTATION: {
        no_jsdoc: { severity: 'LOW', impact: 2, cwe: '', message: 'Exported function missing JSDoc' },
        outdated_comment: { severity: 'LOW', impact: 2, cwe: '', message: 'Comment may be outdated based on code' },
        no_readme: { severity: 'LOW', impact: 2, cwe: '', message: 'Package missing README' },
        no_changelog: { severity: 'LOW', impact: 1, cwe: '', message: 'Package missing CHANGELOG' },
    },

    // ==================== MAINTAINABILITY ====================
    MAINTAINABILITY: {
        tight_coupling: { severity: 'MEDIUM', impact: 4, cwe: '', message: 'Tight coupling between modules' },
        circular_dep: { severity: 'MEDIUM', impact: 5, cwe: '', message: 'Circular dependency detected' },
        import_star: { severity: 'LOW', impact: 2, cwe: '', message: 'Avoid import * - use named imports' },
        any_type: { severity: 'LOW', impact: 2, cwe: '', message: 'TypeScript any type - add proper type' },
        deprecated_api: { severity: 'LOW', impact: 3, cwe: '', message: 'Using deprecated API' },
    },

    // ==================== COVERAGE (NEW) ====================
    COVERAGE: {
        low_coverage_file: { severity: 'LOW', impact: 2, cwe: '', message: 'File has less than 80% test coverage' },
        uncovered_function: { severity: 'LOW', impact: 2, cwe: '', message: 'Function has no test coverage' },
        uncovered_branch: { severity: 'LOW', impact: 2, cwe: '', message: 'Branch not covered by tests' },
        no_coverage_data: { severity: 'INFO', impact: 1, cwe: '', message: 'No coverage data found - run tests with coverage' },
    },

    // ==================== DUPLICATION (NEW) ====================
    DUPLICATION: {
        cross_file_clone: { severity: 'MEDIUM', impact: 4, cwe: '', message: 'Code duplicated across files - extract to shared module' },
        internal_clone: { severity: 'LOW', impact: 3, cwe: '', message: 'Code duplicated within file - extract to function' },
        high_duplication: { severity: 'MEDIUM', impact: 4, cwe: '', message: 'High code duplication ratio detected' },
    },

    // ==================== ACCESSIBILITY (NEW) ====================
    ACCESSIBILITY: {
        missing_alt: { severity: 'LOW', impact: 3, cwe: '', message: 'Image missing alt attribute' },
        missing_label: { severity: 'LOW', impact: 3, cwe: '', message: 'Form input missing label' },
        no_aria_role: { severity: 'LOW', impact: 2, cwe: '', message: 'Interactive element missing ARIA role' },
        color_contrast: { severity: 'MEDIUM', impact: 3, cwe: '', message: 'Insufficient color contrast ratio' },
        keyboard_trap: { severity: 'HIGH', impact: 4, cwe: '', message: 'Keyboard trap - focus cannot escape element' },
        no_focus_visible: { severity: 'LOW', impact: 2, cwe: '', message: 'Focus indicator not visible' },
        no_skip_link: { severity: 'LOW', impact: 2, cwe: '', message: 'No skip to main content link' },
        auto_play: { severity: 'LOW', impact: 2, cwe: '', message: 'Media auto-plays without user consent' },
        no_captions: { severity: 'MEDIUM', impact: 3, cwe: '', message: 'Video without captions' },
        empty_link: { severity: 'LOW', impact: 2, cwe: '', message: 'Link with empty or generic text' },
        no_lang: { severity: 'LOW', impact: 2, cwe: '', message: 'HTML lang attribute missing' },
        no_heading: { severity: 'LOW', impact: 2, cwe: '', message: 'Page without h1 heading' },
        heading_order: { severity: 'LOW', impact: 2, cwe: '', message: 'Heading levels skip numbers' },
        no_landmarks: { severity: 'LOW', impact: 2, cwe: '', message: 'Page without ARIA landmarks' },
        table_no_headers: { severity: 'LOW', impact: 2, cwe: '', message: 'Data table without headers' },
    },

    // ==================== INTERNATIONALIZATION (NEW) ====================
    I18N: {
        hardcoded_string: { severity: 'LOW', impact: 2, cwe: '', message: 'Hardcoded user-facing string' },
        no_locale: { severity: 'LOW', impact: 2, cwe: '', message: 'No locale configuration' },
        date_format: { severity: 'LOW', impact: 2, cwe: '', message: 'Date formatted without locale' },
        currency_format: { severity: 'LOW', impact: 2, cwe: '', message: 'Currency formatted without locale' },
        number_format: { severity: 'LOW', impact: 2, cwe: '', message: 'Number formatted without locale' },
        rtl_support: { severity: 'LOW', impact: 2, cwe: '', message: 'No RTL language support' },
        concat_string: { severity: 'LOW', impact: 2, cwe: '', message: 'Strings concatenated instead of interpolated' },
        plural_handling: { severity: 'LOW', impact: 2, cwe: '', message: 'Pluralization not handled correctly' },
        timezone_issue: { severity: 'MEDIUM', impact: 3, cwe: '', message: 'Timezone not handled correctly' },
        encoding_issue: { severity: 'MEDIUM', impact: 3, cwe: '', message: 'Character encoding issue' },
        missing_translation: { severity: 'LOW', impact: 2, cwe: '', message: 'Missing translation for key' },
        dynamic_key: { severity: 'LOW', impact: 2, cwe: '', message: 'Dynamic translation key may not exist' },
        fallback_locale: { severity: 'LOW', impact: 2, cwe: '', message: 'No fallback locale configured' },
    },
};

module.exports = QUALITY_RULES;
