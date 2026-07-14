import fs from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import { normalizePayload, getAllLayers } from '../src/engine/normalizer'
import { matchAllLayers, loadRules } from '../src/engine/ruleMatcher'
import { parseValidatedRulesFile } from '../src/engine/schemaValidator'
import { detectHomoglyphs } from '../src/engine/homoglyphDetector'

const __dirname = path.dirname(fileURLToPath(import.meta.url))

interface PayloadTestCase {
  id: string
  category: string
  expectedThreats: number
  description: string
  payload: string
}

function loadBenchmarkRules() {
  const rulesPath = path.join(__dirname, '../public/rules/rules.json')
  const rawRules = JSON.parse(fs.readFileSync(rulesPath, 'utf8'))
  const validated = parseValidatedRulesFile(rawRules)
  loadRules(validated)
}

function runBenchmark() {
  console.log('Loading rules...')
  loadBenchmarkRules()

  const dataPath = path.join(__dirname, 'sample-payloads.json')
  const testCases: PayloadTestCase[] = JSON.parse(fs.readFileSync(dataPath, 'utf8'))

  let truePositives = 0
  let falsePositives = 0
  let trueNegatives = 0
  let falseNegatives = 0

  const startTime = Date.now()

  console.log('\nRunning Benchmark...\n')

  testCases.forEach((tc) => {
    // 1. Homoglyph detection
    const { normalized: normalizedText } = detectHomoglyphs(tc.payload)

    // 2. Normalization
    const normalized = normalizePayload(normalizedText)
    const layers = getAllLayers(normalized)

    // 3. Rule matching
    const threats = matchAllLayers(layers)

    const expectedMalicious = tc.expectedThreats > 0
    const actualMalicious = threats.length > 0

    const symbol = actualMalicious === expectedMalicious ? '✅' : '❌'
    
    if (expectedMalicious && actualMalicious) {
      truePositives++
    } else if (!expectedMalicious && !actualMalicious) {
      trueNegatives++
    } else if (!expectedMalicious && actualMalicious) {
      falsePositives++
    } else if (expectedMalicious && !actualMalicious) {
      falseNegatives++
    }

    console.log(`${symbol} [${tc.id}] ${tc.category.padEnd(12)} - Expected: ${expectedMalicious ? 'MALICIOUS' : 'BENIGN'.padEnd(9)} | Actual: ${actualMalicious ? 'MALICIOUS' : 'BENIGN'.padEnd(9)} | ${tc.description}`)
  })

  const endTime = Date.now()
  const durationMs = endTime - startTime

  // Metrics
  const precision = truePositives / (truePositives + falsePositives) || 0
  const recall = truePositives / (truePositives + falseNegatives) || 0
  const f1 = 2 * (precision * recall) / (precision + recall) || 0

  console.log('\n════════ BENCHMARK RESULTS ════════')
  console.log(`Total Cases: ${testCases.length}`)
  console.log(`Time taken:  ${durationMs} ms`)
  console.log(`Avg time:    ${(durationMs / testCases.length).toFixed(2)} ms / payload`)
  console.log('-----------------------------------')
  console.log(`True Positives:  ${truePositives}`)
  console.log(`False Positives: ${falsePositives}`)
  console.log(`True Negatives:  ${trueNegatives}`)
  console.log(`False Negatives: ${falseNegatives}`)
  console.log('-----------------------------------')
  console.log(`Precision: ${(precision * 100).toFixed(1)}%`)
  console.log(`Recall:    ${(recall * 100).toFixed(1)}%`)
  console.log(`F1 Score:  ${(f1 * 100).toFixed(1)}%`)
  console.log('═══════════════════════════════════\n')
}

runBenchmark()
