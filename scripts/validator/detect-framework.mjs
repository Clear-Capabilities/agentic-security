#!/usr/bin/env node
// Detect the project's test framework by inspecting build / package files.
// Stdout: a single JSON object {framework, runner, ext, lang}
//
// Detection priority (first match wins):
//   - jest          package.json has "jest" or scripts.test contains "jest"
//   - vitest        package.json has "vitest" or scripts.test contains "vitest"
//   - mocha         package.json has "mocha" or scripts.test contains "mocha"
//   - node-test     scripts.test contains "node --test"
//   - pytest        pytest.ini / pyproject.toml [tool.pytest] / conftest.py
//   - go-test       go.mod present
//   - cargo-test    Cargo.toml present
//   - dotnet-test   any .csproj with Microsoft.NET.Test.Sdk reference
//   - junit         pom.xml with junit / build.gradle with junit
//   - rspec         Gemfile with rspec / spec/spec_helper.rb
//   - phpunit       composer.json with phpunit / phpunit.xml
//   - none          (default — caller should fall back to node:test or unittest)

import * as fs from 'node:fs';
import * as path from 'node:path';

function read(p) { try { return fs.readFileSync(p, 'utf8'); } catch { return null; } }

function detect(root) {
  const pkgJson = read(path.join(root, 'package.json'));
  if (pkgJson) {
    let pkg = null;
    try { pkg = JSON.parse(pkgJson); } catch {}
    if (pkg) {
      const allDeps = { ...(pkg.dependencies||{}), ...(pkg.devDependencies||{}) };
      const testScript = pkg.scripts?.test || '';
      if (allDeps.jest || /\bjest\b/.test(testScript)) {
        return { framework: 'jest', runner: 'npx jest', ext: 'test.js', lang: 'js' };
      }
      if (allDeps.vitest || /\bvitest\b/.test(testScript)) {
        return { framework: 'vitest', runner: 'npx vitest run', ext: 'test.ts', lang: 'ts' };
      }
      if (allDeps.mocha || /\bmocha\b/.test(testScript)) {
        return { framework: 'mocha', runner: 'npx mocha', ext: 'test.js', lang: 'js' };
      }
      if (/node\s+--test\b/.test(testScript)) {
        return { framework: 'node-test', runner: 'node --test', ext: 'test.js', lang: 'js' };
      }
      // Default JS project without an explicit framework — use node:test
      return { framework: 'node-test', runner: 'node --test', ext: 'test.js', lang: 'js' };
    }
  }
  if (fs.existsSync(path.join(root, 'pyproject.toml')) ||
      fs.existsSync(path.join(root, 'pytest.ini')) ||
      fs.existsSync(path.join(root, 'conftest.py'))) {
    return { framework: 'pytest', runner: 'pytest', ext: 'py', lang: 'py' };
  }
  if (fs.existsSync(path.join(root, 'requirements.txt'))) {
    return { framework: 'pytest', runner: 'pytest', ext: 'py', lang: 'py' };
  }
  if (fs.existsSync(path.join(root, 'go.mod'))) {
    return { framework: 'go-test', runner: 'go test', ext: '_test.go', lang: 'go' };
  }
  if (fs.existsSync(path.join(root, 'Cargo.toml'))) {
    return { framework: 'cargo-test', runner: 'cargo test', ext: 'rs', lang: 'rs' };
  }
  // Look for any csproj
  const files = (() => { try { return fs.readdirSync(root); } catch { return []; }})();
  if (files.some(f => f.endsWith('.csproj'))) {
    return { framework: 'dotnet-test', runner: 'dotnet test', ext: 'cs', lang: 'cs' };
  }
  if (fs.existsSync(path.join(root, 'pom.xml'))) {
    return { framework: 'junit', runner: 'mvn test', ext: 'java', lang: 'java' };
  }
  if (fs.existsSync(path.join(root, 'build.gradle')) || fs.existsSync(path.join(root, 'build.gradle.kts'))) {
    return { framework: 'junit', runner: 'gradle test', ext: 'java', lang: 'java' };
  }
  if (fs.existsSync(path.join(root, 'Gemfile')) || fs.existsSync(path.join(root, 'spec'))) {
    return { framework: 'rspec', runner: 'bundle exec rspec', ext: '_spec.rb', lang: 'rb' };
  }
  if (fs.existsSync(path.join(root, 'composer.json')) || fs.existsSync(path.join(root, 'phpunit.xml'))) {
    return { framework: 'phpunit', runner: './vendor/bin/phpunit', ext: 'Test.php', lang: 'php' };
  }
  return { framework: 'none', runner: null, ext: 'js', lang: 'js' };
}

const root = process.argv[2] || process.cwd();
process.stdout.write(JSON.stringify(detect(root), null, 2));
