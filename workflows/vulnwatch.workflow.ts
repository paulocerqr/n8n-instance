import {
  workflow,
  node,
  trigger,
  sticky,
  placeholder,
  newCredential,
  merge,
  splitInBatches,
  nextBatch,
  languageModel,
  expr,
} from '@n8n/workflow-sdk';

const dailySchedule = trigger({
  type: 'n8n-nodes-base.scheduleTrigger',
  version: 1.3,
  config: {
    name: 'Agendamento diário 07:00',
    parameters: {
      rule: {
        interval: [
          { field: 'days', daysInterval: 1, triggerAtHour: 7, triggerAtMinute: 0 },
        ],
      },
    },
    position: [0, 300],
  },
  output: [{}],
});

const initializeSchema = node({
  type: 'n8n-nodes-base.postgres',
  version: 2.7,
  config: {
    name: 'Inicializar schema VulnWatch',
    parameters: {
      resource: 'database',
      operation: 'executeQuery',
      query:
        'CREATE SCHEMA IF NOT EXISTS vulnwatch;\n' +
        'CREATE TABLE IF NOT EXISTS vulnwatch.vulnerabilities (\n' +
        '  cve_id TEXT PRIMARY KEY,\n' +
        '  published_at TIMESTAMPTZ,\n' +
        '  modified_at TIMESTAMPTZ,\n' +
        '  severity TEXT,\n' +
        '  cvss_score NUMERIC,\n' +
        '  priority TEXT NOT NULL,\n' +
        '  kev BOOLEAN NOT NULL DEFAULT FALSE,\n' +
        '  vendor_project TEXT,\n' +
        '  product TEXT,\n' +
        '  description_raw TEXT,\n' +
        '  summary_pt_br TEXT,\n' +
        '  category TEXT,\n' +
        '  affected_asset_types JSONB,\n' +
        '  recommended_action TEXT,\n' +
        '  llm_confidence NUMERIC,\n' +
        '  needs_human_review BOOLEAN,\n' +
        '  raw_payload JSONB,\n' +
        '  first_seen_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),\n' +
        '  last_seen_at TIMESTAMPTZ NOT NULL DEFAULT NOW()\n' +
        ');\n' +
        'CREATE TABLE IF NOT EXISTS vulnwatch.pipeline_runs (\n' +
        '  execution_id TEXT PRIMARY KEY,\n' +
        '  started_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),\n' +
        '  finished_at TIMESTAMPTZ,\n' +
        '  status TEXT NOT NULL,\n' +
        '  relevant_count INTEGER NOT NULL DEFAULT 0,\n' +
        '  details JSONB\n' +
        ');',
      options: { queryBatching: 'transaction' },
    },
    credentials: { postgres: newCredential('Postgres account') },
    retryOnFail: true,
    maxTries: 3,
    waitBetweenTries: 2000,
    position: [260, 300],
  },
  output: [{ initialized: true }],
});

const fetchNvd = node({
  type: 'n8n-nodes-base.httpRequest',
  version: 4.5,
  config: {
    name: 'Coletar NVD CVE 2.0',
    parameters: {
      method: 'GET',
      url: 'https://services.nvd.nist.gov/rest/json/cves/2.0',
      authentication: 'none',
      sendQuery: true,
      specifyQuery: 'keypair',
      queryParameters: {
        parameters: [
          {
            name: 'lastModStartDate',
            value: expr('{{ $now.minus({ hours: 25 }).toUTC().toISO() }}'),
          },
          { name: 'lastModEndDate', value: expr('{{ $now.toUTC().toISO() }}') },
          { name: 'resultsPerPage', value: '2000' },
          { name: 'noRejected', value: '' },
        ],
      },
      options: {
        timeout: 60000,
        response: { response: { responseFormat: 'json' } },
        pagination: {
          pagination: {
            paginationMode: 'updateAParameterInEachRequest',
            parameters: {
              parameters: [
                {
                  type: 'qs',
                  name: 'startIndex',
                  value: expr('{{ $pageCount * 2000 }}'),
                },
              ],
            },
            paginationCompleteWhen: 'other',
            completeExpression: expr(
              '{{ ($pageCount + 1) * 2000 >= $response.body.totalResults }}',
            ),
            limitPagesFetched: true,
            maxRequests: 10,
            requestInterval: 1000,
          },
        },
      },
    },
    retryOnFail: true,
    maxTries: 3,
    waitBetweenTries: 3000,
    position: [540, 160],
  },
  output: [
    {
      resultsPerPage: 1,
      startIndex: 0,
      totalResults: 1,
      vulnerabilities: [
        {
          cve: {
            id: 'CVE-2026-12345',
            published: '2026-08-20T10:00:00.000',
            lastModified: '2026-08-20T11:00:00.000',
            vulnStatus: 'Analyzed',
            descriptions: [
              { lang: 'en', value: 'Example remote code execution vulnerability.' },
            ],
            metrics: {
              cvssMetricV31: [
                { cvssData: { baseScore: 9.8, baseSeverity: 'CRITICAL' } },
              ],
            },
            references: [{ url: 'https://example.com/advisory' }],
          },
        },
      ],
    },
  ],
});

const splitNvd = node({
  type: 'n8n-nodes-base.splitOut',
  version: 1,
  config: {
    name: 'Separar CVEs NVD',
    parameters: { fieldToSplitOut: 'vulnerabilities', include: 'noOtherFields' },
    position: [800, 160],
  },
  output: [
    {
      cve: {
        id: 'CVE-2026-12345',
        published: '2026-08-20T10:00:00.000',
        lastModified: '2026-08-20T11:00:00.000',
        vulnStatus: 'Analyzed',
        descriptions: [
          { lang: 'en', value: 'Example remote code execution vulnerability.' },
        ],
        metrics: {
          cvssMetricV31: [
            { cvssData: { baseScore: 9.8, baseSeverity: 'CRITICAL' } },
          ],
        },
        references: [{ url: 'https://example.com/advisory' }],
      },
    },
  ],
});

const normalizeNvd = node({
  type: 'n8n-nodes-base.set',
  version: 3.5,
  config: {
    name: 'Normalizar NVD',
    parameters: {
      mode: 'manual',
      includeOtherFields: false,
      assignments: {
        assignments: [
          {
            id: 'nvd-cve-id',
            name: 'cve_id',
            value: expr("{{ $json.cve.id ?? '' }}"),
            type: 'string',
          },
          {
            id: 'nvd-published',
            name: 'published_at',
            value: expr('{{ $json.cve.published ?? null }}'),
            type: 'string',
          },
          {
            id: 'nvd-modified',
            name: 'modified_at',
            value: expr('{{ $json.cve.lastModified ?? null }}'),
            type: 'string',
          },
          {
            id: 'nvd-status',
            name: 'status',
            value: expr("{{ $json.cve.vulnStatus ?? '' }}"),
            type: 'string',
          },
          {
            id: 'nvd-desc',
            name: 'description_raw',
            value: expr(
              "{{ $json.cve.descriptions?.find(d => d.lang === 'en')?.value ?? $json.cve.descriptions?.[0]?.value ?? '' }}",
            ),
            type: 'string',
          },
          {
            id: 'nvd-score',
            name: 'cvss_score',
            value: expr(
              '{{ $json.cve.metrics?.cvssMetricV40?.[0]?.cvssData?.baseScore ?? $json.cve.metrics?.cvssMetricV31?.[0]?.cvssData?.baseScore ?? $json.cve.metrics?.cvssMetricV30?.[0]?.cvssData?.baseScore ?? $json.cve.metrics?.cvssMetricV2?.[0]?.cvssData?.baseScore ?? 0 }}',
            ),
            type: 'number',
          },
          {
            id: 'nvd-severity',
            name: 'severity',
            value: expr(
              "{{ $json.cve.metrics?.cvssMetricV40?.[0]?.cvssData?.baseSeverity ?? $json.cve.metrics?.cvssMetricV31?.[0]?.cvssData?.baseSeverity ?? $json.cve.metrics?.cvssMetricV30?.[0]?.cvssData?.baseSeverity ?? $json.cve.metrics?.cvssMetricV2?.[0]?.baseSeverity ?? 'UNKNOWN' }}",
            ),
            type: 'string',
          },
          {
            id: 'nvd-refs',
            name: 'references',
            value: expr('{{ $json.cve.references ?? [] }}'),
            type: 'array',
          },
          {
            id: 'nvd-raw',
            name: 'raw_nvd',
            value: expr('{{ $json }}'),
            type: 'object',
          },
        ],
      },
    },
    position: [1060, 160],
  },
  output: [
    {
      cve_id: 'CVE-2026-12345',
      published_at: '2026-08-20T10:00:00.000',
      modified_at: '2026-08-20T11:00:00.000',
      status: 'Analyzed',
      description_raw: 'Example remote code execution vulnerability.',
      cvss_score: 9.8,
      severity: 'CRITICAL',
      references: [{ url: 'https://example.com/advisory' }],
      raw_nvd: { cve: { id: 'CVE-2026-12345' } },
    },
  ],
});

const fetchCisa = node({
  type: 'n8n-nodes-base.httpRequest',
  version: 4.5,
  config: {
    name: 'Coletar CISA KEV',
    parameters: {
      method: 'GET',
      url: 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json',
      authentication: 'none',
      options: {
        timeout: 60000,
        response: { response: { responseFormat: 'json' } },
      },
    },
    retryOnFail: true,
    maxTries: 3,
    waitBetweenTries: 3000,
    position: [540, 440],
  },
  output: [
    {
      title: 'CISA Known Exploited Vulnerabilities Catalog',
      vulnerabilities: [
        {
          cveID: 'CVE-2026-12345',
          vendorProject: 'Example Vendor',
          product: 'Example Product',
          vulnerabilityName: 'Example Product Remote Code Execution',
          dateAdded: '2026-08-20',
          shortDescription: 'Example vulnerability.',
          requiredAction: 'Apply mitigations per vendor instructions.',
          dueDate: '2026-09-10',
          knownRansomwareCampaignUse: 'Unknown',
          notes: '',
        },
      ],
    },
  ],
});

const splitCisa = node({
  type: 'n8n-nodes-base.splitOut',
  version: 1,
  config: {
    name: 'Separar catálogo KEV',
    parameters: { fieldToSplitOut: 'vulnerabilities', include: 'noOtherFields' },
    position: [800, 440],
  },
  output: [
    {
      cveID: 'CVE-2026-12345',
      vendorProject: 'Example Vendor',
      product: 'Example Product',
      vulnerabilityName: 'Example Product Remote Code Execution',
      dateAdded: '2026-08-20',
      requiredAction: 'Apply mitigations per vendor instructions.',
      dueDate: '2026-09-10',
      knownRansomwareCampaignUse: 'Unknown',
    },
  ],
});

const normalizeCisa = node({
  type: 'n8n-nodes-base.set',
  version: 3.5,
  config: {
    name: 'Normalizar CISA KEV',
    parameters: {
      mode: 'manual',
      includeOtherFields: false,
      assignments: {
        assignments: [
          {
            id: 'kev-cve-id',
            name: 'cve_id',
            value: expr("{{ $json.cveID ?? '' }}"),
            type: 'string',
          },
          { id: 'kev-flag', name: 'kev', value: true, type: 'boolean' },
          {
            id: 'kev-vendor',
            name: 'vendor_project',
            value: expr("{{ $json.vendorProject ?? '' }}"),
            type: 'string',
          },
          {
            id: 'kev-product',
            name: 'product',
            value: expr("{{ $json.product ?? '' }}"),
            type: 'string',
          },
          {
            id: 'kev-name',
            name: 'vulnerability_name',
            value: expr("{{ $json.vulnerabilityName ?? '' }}"),
            type: 'string',
          },
          {
            id: 'kev-added',
            name: 'kev_date_added',
            value: expr('{{ $json.dateAdded ?? null }}'),
            type: 'string',
          },
          {
            id: 'kev-action',
            name: 'required_action',
            value: expr("{{ $json.requiredAction ?? '' }}"),
            type: 'string',
          },
          {
            id: 'kev-due',
            name: 'due_date',
            value: expr('{{ $json.dueDate ?? null }}'),
            type: 'string',
          },
          {
            id: 'kev-ransomware',
            name: 'known_ransomware_use',
            value: expr(
              "{{ $json.knownRansomwareCampaignUse ?? 'Unknown' }}",
            ),
            type: 'string',
          },
          {
            id: 'kev-raw',
            name: 'raw_kev',
            value: expr('{{ $json }}'),
            type: 'object',
          },
        ],
      },
    },
    position: [1060, 440],
  },
  output: [
    {
      cve_id: 'CVE-2026-12345',
      kev: true,
      vendor_project: 'Example Vendor',
      product: 'Example Product',
      vulnerability_name: 'Example Product Remote Code Execution',
      kev_date_added: '2026-08-20',
      required_action: 'Apply mitigations per vendor instructions.',
      due_date: '2026-09-10',
      known_ransomware_use: 'Unknown',
      raw_kev: { cveID: 'CVE-2026-12345' },
    },
  ],
});

const combineSources = merge({
  version: 3.2,
  config: {
    name: 'Combinar NVD e KEV',
    parameters: {
      mode: 'combine',
      combineBy: 'combineByFields',
      advanced: false,
      fieldsToMatchString: 'cve_id',
      joinMode: 'enrichInput1',
      options: { multipleMatches: 'first' },
    },
    position: [1320, 300],
  },
  output: [
    {
      cve_id: 'CVE-2026-12345',
      published_at: '2026-08-20T10:00:00.000',
      modified_at: '2026-08-20T11:00:00.000',
      status: 'Analyzed',
      description_raw: 'Example remote code execution vulnerability.',
      cvss_score: 9.8,
      severity: 'CRITICAL',
      kev: true,
      vendor_project: 'Example Vendor',
      product: 'Example Product',
      required_action: 'Apply mitigations per vendor instructions.',
      raw_nvd: { cve: { id: 'CVE-2026-12345' } },
      raw_kev: { cveID: 'CVE-2026-12345' },
    },
  ],
});

const calculatePriority = node({
  type: 'n8n-nodes-base.set',
  version: 3.5,
  config: {
    name: 'Calcular prioridade',
    parameters: {
      mode: 'manual',
      includeOtherFields: true,
      assignments: {
        assignments: [
          {
            id: 'priority-kev',
            name: 'kev',
            value: expr('{{ $json.kev ?? false }}'),
            type: 'boolean',
          },
          {
            id: 'priority-level',
            name: 'priority',
            value: expr(
              "{{ $json.kev ? 'critical' : ($json.cvss_score >= 9 ? 'critical' : ($json.cvss_score >= 7 ? 'high' : ($json.cvss_score >= 4 ? 'medium' : 'low'))) }}",
            ),
            type: 'string',
          },
          {
            id: 'priority-complete',
            name: 'metadata_complete',
            value: expr('{{ Boolean($json.description_raw && $json.cvss_score > 0) }}'),
            type: 'boolean',
          },
        ],
      },
    },
    position: [1580, 300],
  },
  output: [
    {
      cve_id: 'CVE-2026-12345',
      published_at: '2026-08-20T10:00:00.000',
      modified_at: '2026-08-20T11:00:00.000',
      status: 'Analyzed',
      description_raw: 'Example remote code execution vulnerability.',
      cvss_score: 9.8,
      severity: 'CRITICAL',
      kev: true,
      priority: 'critical',
      metadata_complete: true,
      vendor_project: 'Example Vendor',
      product: 'Example Product',
      required_action: 'Apply mitigations per vendor instructions.',
      raw_nvd: { cve: { id: 'CVE-2026-12345' } },
      raw_kev: { cveID: 'CVE-2026-12345' },
    },
  ],
});

const selectRelevant = node({
  type: 'n8n-nodes-base.filter',
  version: 2.3,
  config: {
    name: 'Selecionar CVEs relevantes',
    parameters: {
      conditions: {
        options: {
          caseSensitive: true,
          leftValue: '',
          typeValidation: 'strict',
          version: 2,
        },
        conditions: [
          {
            leftValue: expr('{{ $json.cve_id }}'),
            rightValue: '',
            operator: { type: 'string', operation: 'notEmpty' },
          },
          {
            leftValue: expr('{{ $json.status }}'),
            rightValue: 'Rejected',
            operator: { type: 'string', operation: 'notEquals' },
          },
          {
            leftValue: expr('{{ $json.priority }}'),
            rightValue: 'medium',
            operator: { type: 'string', operation: 'notEquals' },
          },
          {
            leftValue: expr('{{ $json.priority }}'),
            rightValue: 'low',
            operator: { type: 'string', operation: 'notEquals' },
          },
        ],
        combinator: 'and',
      },
    },
    position: [1840, 300],
  },
  output: [
    {
      cve_id: 'CVE-2026-12345',
      published_at: '2026-08-20T10:00:00.000',
      modified_at: '2026-08-20T11:00:00.000',
      status: 'Analyzed',
      description_raw: 'Example remote code execution vulnerability.',
      cvss_score: 9.8,
      severity: 'CRITICAL',
      kev: true,
      priority: 'critical',
      vendor_project: 'Example Vendor',
      product: 'Example Product',
      required_action: 'Apply mitigations per vendor instructions.',
      raw_nvd: { cve: { id: 'CVE-2026-12345' } },
      raw_kev: { cveID: 'CVE-2026-12345' },
    },
  ],
});

const removeDuplicates = node({
  type: 'n8n-nodes-base.removeDuplicates',
  version: 2,
  config: {
    name: 'Remover duplicados do lote',
    parameters: {
      operation: 'removeDuplicateInputItems',
      compare: 'selectedFields',
      fieldsToCompare: 'cve_id,modified_at',
      options: { removeOtherFields: false },
    },
    position: [2100, 300],
  },
  output: [
    {
      cve_id: 'CVE-2026-12345',
      published_at: '2026-08-20T10:00:00.000',
      modified_at: '2026-08-20T11:00:00.000',
      status: 'Analyzed',
      description_raw: 'Example remote code execution vulnerability.',
      cvss_score: 9.8,
      severity: 'CRITICAL',
      kev: true,
      priority: 'critical',
      vendor_project: 'Example Vendor',
      product: 'Example Product',
      required_action: 'Apply mitigations per vendor instructions.',
      raw_nvd: { cve: { id: 'CVE-2026-12345' } },
      raw_kev: { cveID: 'CVE-2026-12345' },
    },
  ],
});

const nvidiaModel = languageModel({
  type: '@n8n/n8n-nodes-langchain.lmChatNvidia',
  version: 1,
  config: {
    name: 'Modelo NVIDIA NIM',
    parameters: {
      model: 'nvidia/nemotron-3-nano-30b-a3b',
      options: {
        temperature: 0,
        maxTokens: 1000,
        responseFormat: 'json_object',
        timeout: 60000,
        maxRetries: 1,
      },
    },
    credentials: { nvidiaApi: newCredential('NVIDIA NIM') },
    position: [2630, 610],
  },
});

const enrichWithNim = node({
  type: '@n8n/n8n-nodes-langchain.chainLlm',
  version: 1.9,
  config: {
    name: 'Enriquecer com NVIDIA NIM',
    parameters: {
      promptType: 'define',
      text: expr(
        "{{ 'Analise usando somente os fatos abaixo. Não invente versões, correções ou evidências. Retorne somente um objeto JSON válido, sem Markdown e sem texto adicional, com exatamente estas chaves: summary_pt_br (string de até 350 caracteres), category (string), affected_asset_types (array de strings), recommended_action (string de até 250 caracteres), confidence (número entre 0 e 1) e needs_human_review (boolean). Não crie uma chave externa chamada output.\\n\\nCVE: ' + $json.cve_id + '\\nCVSS: ' + $json.cvss_score + '\\nSeveridade: ' + $json.severity + '\\nEstá no CISA KEV: ' + $json.kev + '\\nDescrição NVD: ' + $json.description_raw + '\\nAção CISA: ' + ($json.required_action ?? 'não disponível') }}",
      ),
      hasOutputParser: false,
      messages: {
        messageValues: [
          {
            type: 'SystemMessagePromptTemplate',
            message:
              'Responda apenas no formato estruturado solicitado. Não exponha raciocínio, não inclua explicações e não crie uma chave externa chamada output.',
          },
        ],
      },
      batching: { batchSize: 1, delayBetweenBatches: 500 },
    },
    subnodes: { model: nvidiaModel },
    onError: 'continueErrorOutput',
    position: [2630, 300],
  },
  output: [
    {
      output: {
        summary_pt_br: 'Vulnerabilidade crítica de execução remota de código.',
        category: 'web_application',
        affected_asset_types: ['server'],
        recommended_action: 'Aplicar as mitigações indicadas pelo fornecedor.',
        confidence: 0.95,
        needs_human_review: false,
      },
    },
  ],
});

const prepareCveForAi = node({
  type: 'n8n-nodes-base.set',
  version: 3.5,
  config: {
    name: 'Preparar contexto do CVE',
    parameters: {
      mode: 'manual',
      includeOtherFields: true,
      assignments: { assignments: [] },
    },
    position: [2520, 300],
  },
  output: [
    {
      cve_id: 'CVE-2026-12345',
      priority: 'critical',
      kev: true,
      description_raw: 'Example remote code execution vulnerability.',
    },
  ],
});

const combineCveAndEnrichment = merge({
  version: 3.2,
  config: {
    name: 'Combinar CVE e enriquecimento',
    parameters: {
      mode: 'combine',
      combineBy: 'combineByPosition',
      options: {},
    },
    position: [3160, 300],
  },
  output: [
    {
      cve_id: 'CVE-2026-12345',
      published_at: '2026-08-20T10:00:00.000',
      modified_at: '2026-08-20T11:00:00.000',
      severity: 'CRITICAL',
      cvss_score: 9.8,
      priority: 'critical',
      kev: true,
      description_raw: 'Example remote code execution vulnerability.',
      output: {
        summary_pt_br: 'Vulnerabilidade crítica de execução remota de código.',
        category: 'web_application',
        affected_asset_types: ['server'],
        recommended_action: 'Aplicar as mitigações indicadas pelo fornecedor.',
        confidence: 0.95,
        needs_human_review: false,
      },
    },
  ],
});

const interpretNvidiaOutput = node({
  type: 'n8n-nodes-base.code',
  version: 2,
  config: {
    name: 'Validar resposta NVIDIA',
    parameters: {
      mode: 'runOnceForEachItem',
      language: 'javaScript',
      jsCode:
        "const source = { ...$json };\n" +
        "const fallback = { summary_pt_br: source.description_raw ?? 'Resumo indisponível', category: 'unclassified', affected_asset_types: [], recommended_action: source.required_action ?? 'Revisão humana necessária', confidence: 0, needs_human_review: true };\n" +
        "let output = fallback;\n" +
        "let aiStatus = 'fallback';\n" +
        "let aiError = source.error ? String(source.error).slice(0, 200) : 'invalid_model_output';\n" +
        "try {\n" +
        "  const raw = source.text ?? source.response ?? source.output ?? { summary_pt_br: source.summary_pt_br, category: source.category, affected_asset_types: source.affected_asset_types, recommended_action: source.recommended_action, confidence: source.confidence, needs_human_review: source.needs_human_review };\n" +
        "  let parsed = raw;\n" +
        "  if (typeof raw === 'string') {\n" +
        "    const cleaned = raw.trim().replace(/^```(?:json)?\\s*/i, '').replace(/\\s*```$/, '');\n" +
        "    try { parsed = JSON.parse(cleaned); } catch {\n" +
        "      const start = cleaned.indexOf('{');\n" +
        "      const end = cleaned.lastIndexOf('}');\n" +
        "      if (start < 0 || end <= start) throw new Error('JSON ausente');\n" +
        "      parsed = JSON.parse(cleaned.slice(start, end + 1));\n" +
        "    }\n" +
        "  }\n" +
        "  if (parsed && typeof parsed.output === 'object') parsed = parsed.output;\n" +
        "  const confidence = Number(parsed?.confidence);\n" +
        "  if (!parsed || typeof parsed.summary_pt_br !== 'string' || typeof parsed.category !== 'string' || !Array.isArray(parsed.affected_asset_types) || typeof parsed.recommended_action !== 'string' || !Number.isFinite(confidence) || typeof parsed.needs_human_review !== 'boolean') throw new Error('Schema inválido');\n" +
        "  output = { summary_pt_br: parsed.summary_pt_br.slice(0, 350), category: parsed.category, affected_asset_types: parsed.affected_asset_types.map(String), recommended_action: parsed.recommended_action.slice(0, 250), confidence: Math.max(0, Math.min(1, confidence)), needs_human_review: parsed.needs_human_review };\n" +
        "  aiStatus = 'success';\n" +
        "  aiError = undefined;\n" +
        "} catch {}\n" +
        "delete source.text;\n" +
        "delete source.response;\n" +
        "delete source.error;\n" +
        "delete source.output;\n" +
        "delete source.summary_pt_br;\n" +
        "delete source.category;\n" +
        "delete source.affected_asset_types;\n" +
        "delete source.recommended_action;\n" +
        "delete source.confidence;\n" +
        "delete source.needs_human_review;\n" +
        "return { json: { ...source, output, ai_status: aiStatus, ...(aiError ? { ai_error: aiError } : {}) } };",
    },
    position: [3290, 300],
  },
  output: [
    {
      cve_id: 'CVE-2026-12345',
      output: {
        summary_pt_br: 'Vulnerabilidade crítica de execução remota de código.',
        category: 'web_application',
        affected_asset_types: ['server'],
        recommended_action: 'Aplicar as mitigações indicadas pelo fornecedor.',
        confidence: 0.95,
        needs_human_review: false,
      },
      ai_status: 'success',
    },
  ],
});

const persistCve = node({
  type: 'n8n-nodes-base.postgres',
  version: 2.7,
  config: {
    name: 'Persistir CVE',
    parameters: {
      resource: 'database',
      operation: 'executeQuery',
      query:
        'INSERT INTO vulnwatch.vulnerabilities (\n' +
        ' cve_id, published_at, modified_at, severity, cvss_score, priority, kev,\n' +
        ' vendor_project, product, description_raw, summary_pt_br, category,\n' +
        ' affected_asset_types, recommended_action, llm_confidence,\n' +
        ' needs_human_review, raw_payload, last_seen_at\n' +
        ') VALUES (\n' +
        " $1, NULLIF($2, '')::timestamptz, NULLIF($3, '')::timestamptz, $4, $5, $6, $7,\n" +
        " NULLIF($8, ''), NULLIF($9, ''), $10, $11, $12, $13::jsonb, $14, $15, $16,\n" +
        ' $17::jsonb, NOW()\n' +
        ')\n' +
        'ON CONFLICT (cve_id) DO UPDATE SET\n' +
        ' published_at = EXCLUDED.published_at,\n' +
        ' modified_at = EXCLUDED.modified_at,\n' +
        ' severity = EXCLUDED.severity,\n' +
        ' cvss_score = EXCLUDED.cvss_score,\n' +
        ' priority = EXCLUDED.priority,\n' +
        ' kev = EXCLUDED.kev,\n' +
        ' vendor_project = EXCLUDED.vendor_project,\n' +
        ' product = EXCLUDED.product,\n' +
        ' description_raw = EXCLUDED.description_raw,\n' +
        ' summary_pt_br = EXCLUDED.summary_pt_br,\n' +
        ' category = EXCLUDED.category,\n' +
        ' affected_asset_types = EXCLUDED.affected_asset_types,\n' +
        ' recommended_action = EXCLUDED.recommended_action,\n' +
        ' llm_confidence = EXCLUDED.llm_confidence,\n' +
        ' needs_human_review = EXCLUDED.needs_human_review,\n' +
        ' raw_payload = EXCLUDED.raw_payload,\n' +
        ' last_seen_at = NOW()\n' +
        'RETURNING cve_id, priority, kev, summary_pt_br, category, llm_confidence;',
      options: {
        queryBatching: 'independently',
        queryReplacement: expr(
          "{{ [ $json.cve_id, $json.published_at ?? '', $json.modified_at ?? '', $json.severity, $json.cvss_score, $json.priority, $json.kev, $json.vendor_project ?? '', $json.product ?? '', $json.description_raw, $json.output.summary_pt_br, $json.output.category, JSON.stringify($json.output.affected_asset_types ?? []), $json.output.recommended_action, $json.output.confidence, $json.output.needs_human_review, JSON.stringify({ nvd: $json.raw_nvd, kev: $json.raw_kev ?? null }) ] }}",
        ),
      },
    },
    credentials: { postgres: newCredential('Postgres account') },
    retryOnFail: true,
    maxTries: 3,
    waitBetweenTries: 2000,
    position: [2900, 300],
  },
  output: [
    {
      cve_id: 'CVE-2026-12345',
      priority: 'critical',
      kev: true,
      summary_pt_br: 'Vulnerabilidade crítica de execução remota de código.',
      category: 'web_application',
      llm_confidence: 0.95,
    },
  ],
});

const updateSheets = node({
  type: 'n8n-nodes-base.googleSheets',
  version: 4.7,
  config: {
    name: 'Atualizar Google Sheets',
    parameters: {
      resource: 'sheet',
      operation: 'appendOrUpdate',
      authentication: 'oAuth2',
      documentId: {
        __rl: true,
        mode: 'list',
        value: '',
        cachedResultName: 'Selecione a planilha VulnWatch',
      },
      sheetName: { __rl: true, mode: 'name', value: 'Vulnerabilities' },
      columns: {
        mappingMode: 'defineBelow',
        matchingColumns: ['cve_id'],
        value: {
          cve_id: expr('{{ $json.cve_id }}'),
          priority: expr('{{ $json.priority }}'),
          kev: expr('{{ $json.kev }}'),
          summary_pt_br: expr('{{ $json.summary_pt_br }}'),
          category: expr('{{ $json.category }}'),
          llm_confidence: expr('{{ $json.llm_confidence }}'),
        },
        schema: [
          {
            id: 'cve_id',
            displayName: 'cve_id',
            required: true,
            defaultMatch: true,
            display: true,
            type: 'string',
            canBeUsedToMatch: true,
          },
          {
            id: 'priority',
            displayName: 'priority',
            required: false,
            defaultMatch: false,
            display: true,
            type: 'string',
            canBeUsedToMatch: false,
          },
          {
            id: 'kev',
            displayName: 'kev',
            required: false,
            defaultMatch: false,
            display: true,
            type: 'boolean',
            canBeUsedToMatch: false,
          },
          {
            id: 'summary_pt_br',
            displayName: 'summary_pt_br',
            required: false,
            defaultMatch: false,
            display: true,
            type: 'string',
            canBeUsedToMatch: false,
          },
          {
            id: 'category',
            displayName: 'category',
            required: false,
            defaultMatch: false,
            display: true,
            type: 'string',
            canBeUsedToMatch: false,
          },
          {
            id: 'llm_confidence',
            displayName: 'llm_confidence',
            required: false,
            defaultMatch: false,
            display: true,
            type: 'number',
            canBeUsedToMatch: false,
          },
        ],
      },
      options: { cellFormat: 'USER_ENTERED' },
      handlingExtraData: 'ignoreIt',
    },
    credentials: {
      googleSheetsOAuth2Api: newCredential('Google Sheets account'),
    },
    onError: 'continueRegularOutput',
    retryOnFail: true,
    maxTries: 2,
    waitBetweenTries: 2000,
    position: [3170, 300],
  },
  output: [
    {
      cve_id: 'CVE-2026-12345',
      priority: 'critical',
      kev: true,
      summary_pt_br: 'Vulnerabilidade crítica de execução remota de código.',
      category: 'web_application',
      llm_confidence: 0.95,
    },
  ],
});

const prepareReportItem = node({
  type: 'n8n-nodes-base.set',
  version: 3.5,
  config: {
    name: 'Preparar item do relatório',
    parameters: {
      mode: 'manual',
      includeOtherFields: false,
      assignments: {
        assignments: [
          {
            id: 'report-cve',
            name: 'cve_id',
            value: expr("{{ $('Persistir CVE').item.json.cve_id }}"),
            type: 'string',
          },
          {
            id: 'report-priority',
            name: 'priority',
            value: expr("{{ $('Persistir CVE').item.json.priority }}"),
            type: 'string',
          },
          {
            id: 'report-kev',
            name: 'kev',
            value: expr("{{ $('Persistir CVE').item.json.kev }}"),
            type: 'boolean',
          },
          {
            id: 'report-summary',
            name: 'summary_pt_br',
            value: expr("{{ $('Persistir CVE').item.json.summary_pt_br }}"),
            type: 'string',
          },
          {
            id: 'report-category',
            name: 'category',
            value: expr("{{ $('Persistir CVE').item.json.category }}"),
            type: 'string',
          },
          {
            id: 'report-confidence',
            name: 'llm_confidence',
            value: expr("{{ $('Persistir CVE').item.json.llm_confidence }}"),
            type: 'number',
          },
        ],
      },
    },
    position: [3440, 300],
  },
  output: [
    {
      cve_id: 'CVE-2026-12345',
      priority: 'critical',
      kev: true,
      summary_pt_br: 'Vulnerabilidade crítica de execução remota de código.',
      category: 'web_application',
      llm_confidence: 0.95,
    },
  ],
});

const enrichLoop = splitInBatches({
  version: 3,
  config: {
    name: 'Enriquecer em lotes',
    parameters: { batchSize: 1, options: { reset: false } },
    position: [2360, 300],
  },
  output: [
    {
      cve_id: 'CVE-2026-12345',
      priority: 'critical',
      kev: true,
      description_raw: 'Example remote code execution vulnerability.',
    },
  ],
});

const aggregateReport = node({
  type: 'n8n-nodes-base.aggregate',
  version: 1,
  config: {
    name: 'Agregar relatório',
    parameters: {
      aggregate: 'aggregateAllItemData',
      destinationFieldName: 'vulnerabilities',
      include: 'specifiedFields',
      fieldsToInclude:
        'cve_id,priority,kev,summary_pt_br,category,llm_confidence',
    },
    executeOnce: true,
    position: [3720, 300],
  },
  output: [
    {
      vulnerabilities: [
        {
          cve_id: 'CVE-2026-12345',
          priority: 'critical',
          kev: true,
          summary_pt_br: 'Vulnerabilidade crítica de execução remota de código.',
          category: 'web_application',
          llm_confidence: 0.95,
        },
      ],
    },
  ],
});

const generateHtml = node({
  type: 'n8n-nodes-base.html',
  version: 1.2,
  config: {
    name: 'Gerar relatório HTML',
    parameters: {
      operation: 'generateHtmlTemplate',
      html: expr(
        '<!doctype html><html><head><meta charset="utf-8"><style>body{font-family:Arial,sans-serif;color:#172033}h1{color:#b42318}li{margin:12px 0}.critical{color:#b42318}.high{color:#b54708}</style></head><body><h1>VulnWatch AI — Relatório diário</h1><p>Execução: {{ $now.toFormat("dd/MM/yyyy HH:mm") }}</p><p>Total de vulnerabilidades prioritárias: <strong>{{ $json.vulnerabilities.length }}</strong></p><ul>{{ $json.vulnerabilities.map(v => \'<li class="\' + v.priority + \'"><strong>\' + v.cve_id + \'</strong> [\' + v.priority.toUpperCase() + \'] — \' + v.summary_pt_br + \'</li>\').join(\'\') }}</ul></body></html>',
      ),
    },
    position: [3990, 300],
  },
  output: [
    {
      html: '<h1>VulnWatch AI — Relatório diário</h1><p>1 vulnerabilidade prioritária.</p>',
    },
  ],
});

const notifyTelegram = node({
  type: 'n8n-nodes-base.telegram',
  version: 1.2,
  config: {
    name: 'Notificar Telegram',
    parameters: {
      resource: 'message',
      operation: 'sendMessage',
      chatId: placeholder(
        'Informe o chat ID do Telegram para os relatórios VulnWatch',
      ),
      text: expr(
        "{{ '🛡️ VulnWatch AI\\n\\n' + $('Agregar relatório').item.json.vulnerabilities.length + ' vulnerabilidades prioritárias processadas.\\n\\n' + $('Agregar relatório').item.json.vulnerabilities.slice(0, 5).map(v => '• ' + v.cve_id + ' [' + v.priority.toUpperCase() + '] — ' + v.summary_pt_br).join('\\n\\n') }}",
      ),
      replyMarkup: 'none',
      additionalFields: {
        appendAttribution: false,
        disable_web_page_preview: true,
      },
    },
    credentials: { telegramApi: newCredential('Telegram account') },
    onError: 'continueRegularOutput',
    retryOnFail: true,
    maxTries: 2,
    waitBetweenTries: 2000,
    position: [4250, 300],
  },
  output: [{ ok: true, result: { message_id: 1, text: 'VulnWatch AI' } }],
});

const logRun = node({
  type: 'n8n-nodes-base.postgres',
  version: 2.7,
  config: {
    name: 'Registrar execução',
    parameters: {
      resource: 'database',
      operation: 'executeQuery',
      query:
        'INSERT INTO vulnwatch.pipeline_runs (execution_id, finished_at, status, relevant_count, details)\n' +
        'VALUES ($1, NOW(), $2, $3, $4::jsonb)\n' +
        'ON CONFLICT (execution_id) DO UPDATE SET\n' +
        ' finished_at = EXCLUDED.finished_at,\n' +
        ' status = EXCLUDED.status,\n' +
        ' relevant_count = EXCLUDED.relevant_count,\n' +
        ' details = EXCLUDED.details\n' +
        'RETURNING execution_id, status, relevant_count;',
      options: {
        queryBatching: 'single',
        queryReplacement: expr(
          "{{ [ $execution.id, 'success', $('Agregar relatório').item.json.vulnerabilities.length, JSON.stringify({ report_generated: true, telegram_attempted: true }) ] }}",
        ),
      },
    },
    credentials: { postgres: newCredential('Postgres account') },
    retryOnFail: true,
    maxTries: 3,
    waitBetweenTries: 2000,
    position: [4510, 300],
  },
  output: [{ execution_id: '123', status: 'success', relevant_count: 1 }],
});

const prerequisitesNote = sticky(
  '## Pré-requisitos antes de publicar\n\n' +
    '1. Confirmar que **Postgres account** aponta para um banco dedicado ou autorizar o schema vulnwatch.\n' +
    '2. Criar a credencial **NVIDIA NIM** no n8n.\n' +
    '3. Selecionar a planilha e criar a aba **Vulnerabilities** com os cabeçalhos configurados.\n' +
    '4. Informar o chat ID do Telegram.\n' +
    '5. Opcional: adicionar uma credencial NVD API para limites maiores.',
  [initializeSchema],
  { color: 5 },
);

const sourcesNote = sticky(
  '## Fontes oficiais\n\n' +
    '- NVD CVE API 2.0: detalhes técnicos, CVSS, datas e referências.\n' +
    '- CISA KEV: vulnerabilidades comprovadamente exploradas.\n\n' +
    'O LLM apenas resume e classifica; ele não substitui os fatos das fontes.',
  [fetchNvd, splitNvd, normalizeNvd, fetchCisa, splitCisa, normalizeCisa],
  { color: 4 },
);

export default workflow(
  'vulnwatch-ai',
  'VulnWatch AI — Vulnerability Intelligence Pipeline',
)
  .add(dailySchedule)
  .to(initializeSchema)
  .to(fetchNvd.to(splitNvd.to(normalizeNvd.to(combineSources.input(0)))))
  .add(initializeSchema)
  .to(fetchCisa.to(splitCisa.to(normalizeCisa.to(combineSources.input(1)))))
  .add(combineSources)
  .to(calculatePriority)
  .to(selectRelevant)
  .to(removeDuplicates)
  .to(
    enrichLoop
      .onEachBatch(
        prepareCveForAi.to(
          enrichWithNim.to(combineCveAndEnrichment.input(1)),
        ),
      )
      .onDone(
        aggregateReport.to(generateHtml).to(notifyTelegram).to(logRun),
      ),
  )
  .add(prepareCveForAi.to(combineCveAndEnrichment.input(0)))
  .add(
    enrichWithNim.onError(combineCveAndEnrichment.input(1)),
  )
  .add(combineCveAndEnrichment)
  .to(interpretNvidiaOutput)
  .to(persistCve)
  .to(updateSheets)
  .to(prepareReportItem)
  .to(nextBatch(enrichLoop))
  .add(prerequisitesNote)
  .add(sourcesNote)
  .group(
    'Coleta e normalização',
    [
      initializeSchema,
      fetchNvd,
      splitNvd,
      normalizeNvd,
      fetchCisa,
      splitCisa,
      normalizeCisa,
      combineSources,
    ],
    {
      description:
        'Coleta NVD e CISA KEV e combina os registros pelo identificador CVE.',
    },
  )
  .group(
    'Validação e priorização',
    [calculatePriority, selectRelevant, removeDuplicates],
    {
      description:
        'Valida, classifica por regras determinísticas e remove duplicados.',
    },
  )
  .group(
    'IA e persistência',
    [
      enrichWithNim,
      nvidiaModel,
      prepareCveForAi,
      combineCveAndEnrichment,
      interpretNvidiaOutput,
      persistCve,
      updateSheets,
      prepareReportItem,
    ],
    {
      description:
        'Enriquece com NVIDIA NIM, aplica fallback seguro e persiste os resultados.',
    },
  )
  .group(
    'Relatório',
    [aggregateReport, generateHtml, notifyTelegram, logRun],
    {
      description:
        'Gera o resumo diário, notifica no Telegram e registra a execução.',
    },
  );
