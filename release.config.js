/**
 * The version comes from the commit messages (Conventional Commits), never typed by hand: feat → minor, fix / perf →
 * patch, a `!` or BREAKING CHANGE footer → major. package.json keeps a placeholder; the release workflow stamps the
 * real version into the packages it publishes.
 *
 * The workflow runs this twice. A dry run first: verifyReleaseCmd writes the next version to .VERSION, and the
 * workflow packs, attests and publishes to both registries with it. Then the real run, which only tags and creates
 * the GitHub release with the assets. So a publish that fails leaves no tag behind and the job can be re-run.
 */
const types = [
  { type: "feat", section: "Features" },
  { type: "fix", section: "Bug Fixes" },
  { type: "perf", section: "Performance" },
  { type: "revert", section: "Reverts" },
  { type: "docs", section: "Documentation" },
  { type: "build", section: "Build System", hidden: true },
  { type: "ci", section: "CI", hidden: true },
  { type: "chore", section: "Chores", hidden: true },
  { type: "refactor", section: "Refactoring", hidden: true },
  { type: "test", section: "Tests", hidden: true }
];

export default {
  tagFormat: "v${version}",
  branches: ["main"],
  plugins: [
    ["@semantic-release/commit-analyzer", { preset: "conventionalcommits", presetConfig: { types } }],
    ["@semantic-release/release-notes-generator", { preset: "conventionalcommits", presetConfig: { types } }],
    ["@semantic-release/exec", { verifyReleaseCmd: "echo ${nextRelease.version} > .VERSION" }],
    [
      "@semantic-release/github",
      {
        assets: [{ path: "assets/*" }],

        // Tag and release only: no comments or labels on issues and pull requests, so the job needs no write access to them.
        successComment: false,
        failComment: false,
        releasedLabels: false
      }
    ]
  ]
};
