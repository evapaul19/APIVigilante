import { useEffect, useState } from 'react'
import { Route, Routes } from 'react-router-dom'
import { AppShell } from './components/AppShell'
import { ErrorBoundary } from './components/States'
import { DEFAULT_FORM, loadPersistedForm, persistForm } from './lib/storage'
import { OverviewPage } from './pages/OverviewPage'
import { NewAssessmentPage } from './pages/NewAssessmentPage'
import { AssessmentPage } from './pages/AssessmentPage'
import { FindingPage } from './pages/FindingPage'
import { ReportPage } from './pages/ReportPage'
import { RecentPage } from './pages/RecentPage'
import type { AssessmentFormState } from './types'

export default function App() {
  const [form, setForm] = useState<AssessmentFormState>(DEFAULT_FORM)
  const [hydrated, setHydrated] = useState(false)

  useEffect(() => {
    setForm(loadPersistedForm())
    setHydrated(true)
  }, [])

  useEffect(() => {
    if (hydrated) persistForm(form)
  }, [form, hydrated])

  return (
    <AppShell>
      <ErrorBoundary>
        <Routes>
          <Route path="/" element={<OverviewPage />} />
          <Route path="/new-assessment" element={<NewAssessmentPage form={form} setForm={setForm} />} />
          <Route path="/recent" element={<RecentPage />} />
          <Route path="/assessment/:scanId" element={<AssessmentPage />} />
          <Route path="/assessment/:scanId/results" element={<AssessmentPage />} />
          <Route path="/assessment/:scanId/finding/:findingId" element={<FindingPage />} />
          <Route path="/assessment/:scanId/report" element={<ReportPage />} />
          <Route path="*" element={<OverviewPage />} />
        </Routes>
      </ErrorBoundary>
    </AppShell>
  )
}
