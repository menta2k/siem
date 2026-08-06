import js from '@eslint/js'
import pluginVue from 'eslint-plugin-vue'
import vueTsEslintConfig from '@vue/eslint-config-typescript'

export default [
  {
    ignores: [
      'dist/**',
      'coverage/**',
      'node_modules/**',
      'src/api/schema.d.ts',
      'playwright-report/**',
      'test-results/**',
    ],
  },
  js.configs.recommended,
  ...pluginVue.configs['flat/recommended'],
  ...vueTsEslintConfig(),
  {
    rules: {
      // FR-027 (release blocker): log fields are attacker-controlled input. There is no
      // legitimate v-html in this application — this rule is the enforcement mechanism,
      // not a style preference.
      'vue/no-v-html': 'error',

      'no-console': ['error', { allow: ['warn', 'error'] }],
      '@typescript-eslint/no-explicit-any': 'error',
      '@typescript-eslint/no-unused-vars': ['error', { argsIgnorePattern: '^_' }],
      'vue/multi-word-component-names': 'off',

      // Vuetify data tables address their slots with dotted names (#item.vendor).
      // The rule reads the dot as a modifier and flags every one; allowModifiers is
      // the documented accommodation, not a workaround.
      'vue/valid-v-slot': ['error', { allowModifiers: true }],

      // Single quotes are correct when the attribute value contains double quotes,
      // as a JSON placeholder does. avoidEscape keeps the rule without forcing
      // backslash soup.
      'vue/html-quotes': ['error', 'double', { avoidEscape: true }],

      // Formatting belongs to Prettier. Leaving these on makes the two tools fight
      // and buries real findings under whitespace noise, which is how a genuine
      // warning ends up ignored.
      'vue/max-attributes-per-line': 'off',
      'vue/singleline-html-element-content-newline': 'off',
      'vue/html-self-closing': 'off',
      'vue/html-indent': 'off',
      'vue/html-closing-bracket-newline': 'off',
      'vue/attributes-order': 'off',
      'vue/first-attribute-linebreak': 'off',
    },
  },
]
