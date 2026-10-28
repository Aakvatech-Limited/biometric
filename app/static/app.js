// Biometric Sync interface behaviour. Plain JavaScript, no framework, no build.
//
// Pages arrive fully rendered from Flask (app/templates). This script adds
// what HTML alone can't: local times, filters, live refresh when a sync
// finishes, the buttons that call /api/*, toasts, dialogs, dark mode and the
// update popup. Clicks are handled by delegation on the document, so regions
// swapped in by a live refresh need no re-binding.
'use strict'

const $ = (sel, root = document) => root.querySelector(sel)
const $$ = (sel, root = document) => [...root.querySelectorAll(sel)]
const ICONS = document.querySelector('link[rel=stylesheet]').href.replace(/frappe\.css.*$/, 'icons.svg')
const wait = (ms) => new Promise((resolve) => setTimeout(resolve, ms))
const number = new Intl.NumberFormat()

// ------------------------------------------------------------------ Requests

async function request(url, { method = 'GET', body } = {}) {
  const response = await fetch(url, {
    method,
    cache: 'no-store',
    headers: body === undefined ? {} : { 'Content-Type': 'application/json' },
    body: body === undefined ? undefined : JSON.stringify(body),
  })
  let data
  try {
    data = await response.json()
  } catch {
    throw new Error(`The app answered ${response.status} ${response.statusText}.`)
  }
  return { ok: response.ok, data }
}

// /api/ui/* answers {data} or {errors: [{message}]}.
async function uiApi(method, path, body) {
  const { data } = await request(`/api/ui${path}`, { method, body })
  if (data.errors?.length) throw new Error(data.errors[0].message)
  return data.data
}

// A button's spinner while its request runs.
function busy(button, on) {
  if (!button) return
  button.disabled = on
  button.classList.toggle('loading', on)
  const use = $('use', button)
  if (!use) return
  if (on) {
    use.dataset.icon = use.getAttribute('href')
    use.setAttribute('href', `${ICONS}#loader-circle`)
  } else if (use.dataset.icon) {
    use.setAttribute('href', use.dataset.icon)
  }
}

// ------------------------------------------------------------------- Toasts

// Returns the toast element; pass `sticky` to keep it until it is removed.
function toast(type, title, description, { sticky = false } = {}) {
  const el = document.createElement('div')
  el.className = `toast ${type}`
  el.setAttribute('role', type === 'error' ? 'alert' : 'status')
  const icon = { success: 'circle-check', error: 'circle-x', warning: 'triangle-alert', loading: 'loader-circle' }[type] || 'info'
  el.innerHTML = `<svg class="icon${type === 'loading' ? ' spin' : ''}" aria-hidden="true"><use href="${ICONS}#${icon}"/></svg><div><div></div><div class="toast-desc"></div></div>`
  el.children[1].children[0].textContent = title
  const desc = el.querySelector('.toast-desc')
  description ? (desc.textContent = description) : desc.remove()
  $('[data-toasts]').append(el)
  if (!sticky) setTimeout(() => el.remove(), type === 'error' ? 7000 : 4000)
  return el
}

// A toast to show after navigating to another page.
function toastAfterNavigate(type, title, description) {
  try {
    sessionStorage.setItem('toast', JSON.stringify([type, title, description]))
  } catch {}
}

function showPendingToast() {
  try {
    const saved = sessionStorage.getItem('toast')
    if (!saved) return
    sessionStorage.removeItem('toast')
    toast(...JSON.parse(saved))
  } catch {}
}

// ---------------------------------------------------------------- Dialogs

function confirmDialog({ title, text, ok = 'Delete' }) {
  const dialog = $('[data-confirm]')
  $('[data-confirm-title]', dialog).textContent = title
  $('[data-confirm-text]', dialog).textContent = text
  $('[data-confirm-ok]', dialog).textContent = ok
  return new Promise((resolve) => {
    const done = (answer) => {
      dialog.close()
      resolve(answer)
    }
    $('[data-confirm-ok]', dialog).onclick = () => done(true)
    $('[data-confirm-cancel]', dialog).onclick = () => done(false)
    dialog.oncancel = () => resolve(false)
    dialog.showModal()
  })
}

// ------------------------------------------------------------------- Times

const timezone = Intl.DateTimeFormat().resolvedOptions().timeZone || 'local time'

function formatTime(date, { year = false, seconds = false } = {}) {
  return new Intl.DateTimeFormat(undefined, {
    day: '2-digit',
    month: 'short',
    year: year ? 'numeric' : undefined,
    hour: '2-digit',
    minute: '2-digit',
    second: seconds ? '2-digit' : undefined,
    hour12: false,
  }).format(date)
}

// "Just now", "4 min ago", "3 h ago", then the date.
function relativeTime(date) {
  const seconds = Math.round((Date.now() - date.getTime()) / 1000)
  if (seconds < 45) return 'Just now'
  if (seconds < 3600) return `${Math.max(1, Math.round(seconds / 60))} min ago`
  if (seconds < 86400) return `${Math.round(seconds / 3600)} h ago`
  return formatTime(date, { year: seconds > 300 * 86400 })
}

function renderTimes(root = document) {
  for (const el of $$('time[datetime]', root)) {
    const date = new Date(el.getAttribute('datetime'))
    if (Number.isNaN(date.getTime())) continue
    const fmt = el.dataset.fmt
    el.textContent =
      fmt === 'abs' ? formatTime(date, { seconds: true })
      : fmt === 'short' ? formatTime(date)
      : fmt === 'full' ? formatTime(date, { year: true })
      : relativeTime(date)
    if (fmt === 'rel') el.title = formatTime(date, { year: true, seconds: true })
  }
  for (const el of $$('[data-tz]', root)) el.textContent = timezone
}

// ----------------------------------------------------------------- Filters

// Filter choices per list, kept across live refreshes.
const filters = {}

function applyFilters(group) {
  const name = group.dataset.filterGroup
  const state = (filters[name] ||= { tab: 'all', q: '', device: '' })
  for (const tab of $$('[data-filter-tab]', group))
    tab.setAttribute('aria-pressed', String(tab.dataset.filterTab === state.tab))
  const search = $('[data-filter-search]', group)
  if (search && search.value !== state.q) search.value = state.q
  const device = $('[data-filter-device]', group)
  if (device) device.value = state.device

  const q = state.q.trim().toLowerCase()
  let shown = 0
  for (const row of $$('[data-row]', group)) {
    const tags = (row.dataset.tags || '').split(' ')
    const visible =
      (state.tab === 'all' || tags.includes(state.tab)) &&
      (!q || (row.dataset.search || '').includes(q)) &&
      (!state.device || row.dataset.device === state.device)
    row.hidden = !visible
    if (visible) shown++
  }
  const none = $('[data-no-match]', group)
  if (none) none.hidden = shown > 0 || !$('[data-row]', group)
}

function applyAllFilters(root = document) {
  for (const group of $$('[data-filter-group]', root)) applyFilters(group)
}

function filterState(el) {
  const group = el.closest('[data-filter-group]')
  return [group, (filters[group.dataset.filterGroup] ||= { tab: 'all', q: '', device: '' })]
}

// ------------------------------------------------------------ Live refresh

// Re-fetch this page and swap in its live regions (lists, counts, states).
async function refresh() {
  const regions = $$('[data-live]')
  if (!regions.length) return
  // Don't pull a search box out from under someone typing in it.
  if (document.activeElement?.matches('input, select') && document.activeElement.closest('[data-live]')) return
  try {
    const response = await fetch(location.href, { cache: 'no-store' })
    if (!response.ok) return
    const fresh = new DOMParser().parseFromString(await response.text(), 'text/html')
    const next = $$('[data-live]', fresh)
    regions.forEach((region, i) => {
      if (!next[i]) return
      region.innerHTML = next[i].innerHTML
      renderTimes(region)
      applyAllFilters(region)
    })
    // Header buttons (Sync on a device's page) follow the device's state too.
    for (const button of $$('.page-header [data-action="sync"]')) {
      const fresher = $(`.page-header [data-action="sync"][data-id="${button.dataset.id}"]`, fresh)
      if (fresher && !button.classList.contains('loading')) button.disabled = fresher.disabled
    }
  } catch {
    // Offline for a moment; the next poll tries again.
  }
}

// Syncs started from this tab; their own completion refreshes the page.
let ownSyncs = 0
const sync = { lastLogId: null, syncing: '', scheduler: null }

async function pollState() {
  if (document.visibilityState !== 'visible') return
  try {
    const { ok, data } = await request('/api/sync-state')
    if (!ok) return
    const syncing = (data.syncing || []).map((d) => d.name).join(', ')
    const changed = sync.lastLogId !== null && (data.last_log_id !== sync.lastLogId || syncing !== sync.syncing)
    sync.lastLogId = data.last_log_id
    sync.syncing = syncing
    sync.scheduler = Boolean(data.scheduler_running)
    renderSyncState()
    if (changed && !ownSyncs && !$('dialog[open]') && !$('.menu:not([hidden])')) refresh()
  } catch {
    // A transient polling failure should not disrupt the page.
  }
}

function renderSyncState() {
  $('[data-scheduler-text]').textContent = sync.scheduler ? 'Scheduler running' : 'Scheduler stopped'
  $('[data-scheduler-dot]').className = `dot ${sync.scheduler ? 'green' : 'red'}`
  $('[data-syncing]').hidden = !sync.syncing
  $('[data-syncing-text]').textContent = `Syncing: ${sync.syncing}`
}

// -------------------------------------------------------------- Dark mode

function currentTheme() {
  const chosen = document.documentElement.dataset.theme
  if (chosen) return chosen
  return matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light'
}

function renderThemeButton() {
  const dark = currentTheme() === 'dark'
  const button = $('[data-theme-toggle]')
  $('[data-when-light]', button).hidden = dark
  $('[data-when-dark]', button).hidden = !dark
  button.title = dark ? 'Light mode' : 'Dark mode'
  button.setAttribute('aria-label', button.title)
}

function toggleTheme() {
  const next = currentTheme() === 'dark' ? 'light' : 'dark'
  const root = document.documentElement
  root.classList.add('no-transition')
  root.dataset.theme = next
  try {
    localStorage.setItem('theme', next)
  } catch {}
  renderThemeButton()
  requestAnimationFrame(() => requestAnimationFrame(() => root.classList.remove('no-transition')))
}

// ------------------------------------------------------------- Device rows

async function syncDevice(button) {
  const { id, name } = button.dataset
  busy(button, true)
  ownSyncs++
  try {
    const { data } = await request(`/api/sync/${id}`, { method: 'POST' })
    if (data.success) {
      const log = data.log
      toast('success', name, `Pulled ${number.format(log.records_pulled)}, pushed ${number.format(log.records_pushed)}, skipped ${number.format(log.records_skipped)}.`)
    } else {
      toast('error', name, data.error || data.log?.message || 'Sync failed.')
    }
  } catch (e) {
    toast('error', name, e.message || 'Network error.')
  } finally {
    ownSyncs--
    busy(button, false)
    await refresh()
  }
}

async function syncAll(button) {
  busy(button, true)
  ownSyncs++
  try {
    const { data } = await request('/api/sync/all', { method: 'POST' })
    if (data.success) {
      const failed = data.logs.filter((l) => l.status === 'Failed').length
      const message = `Synced ${data.logs.length} device(s).`
      failed ? toast('warning', message, `${failed} failed. See the logs below.`) : toast('success', message)
    } else {
      toast('error', 'Sync failed', data.error)
    }
  } catch (e) {
    toast('error', 'Sync failed', e.message || 'Network error.')
  } finally {
    ownSyncs--
    busy(button, false)
    await refresh()
  }
}

async function testDevice(button) {
  const { id, name } = button.dataset
  const pending = toast('loading', `Testing ${name}…`, null, { sticky: true })
  try {
    const { data } = await request(`/api/test-device/${id}`, { method: 'POST' })
    if (data.success) {
      const sn = data.device_info?.serialnumber
      toast('success', name, data.message || `Connected.${sn ? ` Serial number: ${sn}` : ''}`)
    } else {
      toast('error', name, data.message)
    }
  } catch (e) {
    toast('error', name, e.message || 'Network error.')
  } finally {
    pending.remove()
  }
}

async function deleteDevice(button) {
  const { id, name, what } = button.dataset
  if (!(await confirmDialog({ title: `Delete ${name}?`, text: `${what} Punches already sent to ERPNext stay there.` }))) return
  try {
    await uiApi('DELETE', `/devices/${id}`)
    toast('success', `Deleted ${name}.`)
    await refresh()
  } catch (e) {
    toast('error', e.message)
  }
}

// ------------------------------------------------------------- Device form

function formFields(form) {
  const fields = {}
  for (const el of form.elements) {
    if (!el.name || el.disabled) continue
    if (el.type === 'radio') {
      if (el.checked) fields[el.name] = el.value
    } else if (el.type === 'checkbox' && el.dataset.list) {
      ;(fields[el.name] ||= []).push(...(el.checked ? [el.value] : []))
    } else {
      fields[el.name] = el.type === 'checkbox' ? el.checked : el.value
    }
  }
  return fields
}

function showFormError(form, message) {
  const el = $('[data-form-error]', form)
  el.textContent = message || ''
  el.hidden = !message
}

// Shift types come from ERPNext when it is configured; otherwise they stay
// a comma-separated text field.
async function loadShiftTypes() {
  const field = $('[data-shift-field]')
  if (!field) return
  let options
  try {
    const { data } = await request('/api/shift-types')
    if (!data.success || !data.shift_types?.length) return
    options = data.shift_types
  } catch {
    return
  }
  const selected = JSON.parse(field.dataset.selected || '[]')
  const names = [...new Set([...options, ...selected])]
  const text = $('input[name=shift_types]', field)
  const box = document.createElement('div')
  box.className = 'checks'
  for (const name of names) {
    const label = document.createElement('label')
    label.className = 'check-chip'
    label.innerHTML = '<input type="checkbox" name="shift_types" data-list="1"> <span></span>'
    label.firstChild.value = name
    label.firstChild.checked = selected.includes(name)
    label.lastChild.textContent = name
    box.append(label)
  }
  text.replaceWith(box)
  $('[data-shift-help]', field).textContent = 'After each sync, “Last Sync of Checkin” is updated on these shift types.'
}

async function saveDevice(form) {
  const button = $('[type=submit]', form)
  const id = form.dataset.id
  showFormError(form, '')
  busy(button, true)
  const fields = formFields(form)
  if ($('[data-list]', form) && !fields.shift_types) fields.shift_types = []
  try {
    const d = await uiApi(id ? 'PUT' : 'POST', id ? `/devices/${id}` : '/devices', fields)
    toastAfterNavigate('success', id ? `Saved ${d.name}.` : `Added ${d.name}.`)
    location.href = '/devices'
  } catch (e) {
    showFormError(form, e.message)
    busy(button, false)
  }
}

// ---------------------------------------------------------------- Settings

async function saveSettings(form, { quiet = false } = {}) {
  const button = $('[type=submit]', form)
  showFormError(form, '')
  if (!quiet) busy(button, true)
  try {
    const result = await uiApi('PUT', '/settings', formFields(form))
    if (!quiet) for (const m of result.messages) toast(m.type, m.text)
    return true
  } catch (e) {
    showFormError(form, e.message)
    return false
  } finally {
    busy(button, false)
  }
}

// The tests check the saved credentials, so save what is typed first.
async function testSettings(button) {
  const form = button.closest('form')
  if (!(await saveSettings(form, { quiet: true }))) return
  busy(button, true)
  try {
    const result = await uiApi('POST', button.dataset.test)
    toast(result.success ? 'success' : 'error', result.message)
  } catch (e) {
    toast('error', e.message)
  } finally {
    busy(button, false)
  }
}

function toggleReveal(button) {
  const input = $('input', button.parentElement)
  const show = input.type === 'password'
  input.type = show ? 'text' : 'password'
  $('use', button).setAttribute('href', `${ICONS}#${show ? 'eye-off' : 'eye'}`)
  button.title = show ? 'Hide' : 'Show'
  button.setAttribute('aria-label', button.title)
}

// ------------------------------------------------------ Background service

function serviceMessage(theme, text) {
  const el = $('[data-service-message]')
  el.className = `notice ${theme}`
  el.textContent = text
  el.hidden = !text
}

async function loadService() {
  const badge = $('[data-service-badge]')
  if (!badge) return
  let installed = null
  try {
    installed = Boolean((await request('/api/service/info')).data.installed)
  } catch {}
  badge.innerHTML =
    installed === null ? '<span class="badge">Unknown</span>'
    : installed ? '<span class="badge green">Installed, starts on boot</span>'
    : '<span class="badge">Not installed</span>'
  $('[data-service-install]').disabled = installed === true
  $('[data-service-remove]').disabled = installed !== true
}

async function installService(button) {
  busy(button, true)
  serviceMessage('blue', 'Installing background service…')
  try {
    const { data } = await request('/api/service/start', { method: 'POST' })
    if (!data.success) throw new Error(data.error || 'Install failed')
    if (data.handoff) {
      serviceMessage('green', `${data.message} The page will reload once the background service is up.`)
      // The foreground process exits in a few seconds; reload once the service answers.
      setTimeout(function poll() {
        fetch('/api/service/info')
          .then(() => location.reload())
          .catch(() => setTimeout(poll, 1500))
      }, 6000)
      return
    }
    serviceMessage('green', data.message)
  } catch (e) {
    serviceMessage('red', `Error: ${e.message}`)
  }
  busy(button, false)
  loadService()
}

async function removeService(button) {
  const ok = await confirmDialog({
    title: 'Remove the background service?',
    text: 'The app will no longer start automatically when this computer starts.',
    ok: 'Remove',
  })
  if (!ok) return
  busy(button, true)
  try {
    const { data } = await request('/api/service/stop', { method: 'POST' })
    if (!data.success) throw new Error(data.error || 'Uninstall failed')
    serviceMessage('green', data.message)
  } catch {
    // When this process IS the background service, it is stopped mid-request
    // and the fetch fails, which still means it was removed.
    serviceMessage('amber', 'Background service removed. If the page stops responding, start the app again with the setup script.')
  }
  busy(button, false)
  loadService()
}

// ----------------------------------------------------------------- Updates

// Shown when the official repo has commits this install lacks. "Later"
// hides it until an even newer commit is published.
const updates = { info: null, checking: false }

function dismissedSha() {
  try {
    return localStorage.getItem('updateDismissedSha')
  } catch {
    return null
  }
}

function renderUpdates() {
  const info = updates.info
  for (const el of $$('[data-open-update]')) el.hidden = !info?.available
  const version = $('[data-update-version]')
  if (version) version.textContent = info?.current_sha || 'unknown'
  const state = $('[data-update-state]')
  if (state)
    state.textContent =
      updates.checking ? 'Checking…'
      : !info ? 'Not checked yet.'
      : !info.supported ? 'Automatic updates need the app to be installed from git.'
      : info.error ? `Could not check for updates: ${info.error}`
      : info.available ? `${info.behind} new change(s) available.`
      : info.checked_at ? `Up to date (checked ${info.checked_at}).`
      : 'Not checked yet.'
}

function openUpdateDialog() {
  const info = updates.info
  if (!info) return
  const dialog = $('[data-update-dialog]')
  const behind = info.behind || 0
  $('[data-update-title]', dialog).textContent = `Update available: ${behind} new change${behind === 1 ? '' : 's'}`
  const list = $('[data-update-commits]', dialog)
  list.replaceChildren(
    ...(info.commits || []).map((c) => {
      const li = document.createElement('li')
      li.innerHTML = '<code></code> <span></span> <span class="muted"></span>'
      li.children[0].textContent = c.sha
      li.children[1].textContent = c.subject
      li.children[2].textContent = `· ${c.date}`
      return li
    }),
  )
  if (behind > (info.commits || []).length) {
    const more = document.createElement('li')
    more.className = 'muted'
    more.textContent = `…and ${behind - info.commits.length} more`
    list.append(more)
  }
  dialog.showModal()
}

function dismissUpdate() {
  try {
    if (updates.info?.remote_sha) localStorage.setItem('updateDismissedSha', updates.info.remote_sha)
  } catch {}
  $('[data-update-dialog]').close()
}

async function loadUpdates() {
  try {
    updates.info = (await request('/api/update/status')).data
  } catch {
    return // offline
  }
  renderUpdates()
  if (updates.info?.available && updates.info.remote_sha !== dismissedSha()) openUpdateDialog()
}

async function checkUpdates(button) {
  updates.checking = true
  renderUpdates()
  busy(button, true)
  try {
    updates.info = (await request('/api/update/check', { method: 'POST' })).data
    if (updates.info.available) openUpdateDialog()
  } catch {
    toast('error', 'Could not reach the app.')
  } finally {
    updates.checking = false
    busy(button, false)
    renderUpdates()
  }
}

async function applyUpdate(button) {
  const dialog = $('[data-update-dialog]')
  const error = $('[data-update-error]', dialog)
  const progress = $('[data-update-progress]', dialog)
  const later = $('[data-update-later]', dialog)
  error.hidden = true
  busy(button, true)
  later.disabled = true
  $('span', button).textContent = 'Updating…'
  dialog.oncancel = (e) => e.preventDefault() // not dismissible while updating
  try {
    const { data } = await request('/api/update/apply', { method: 'POST' })
    if (!data.success) throw new Error(data.message || 'Update failed')
    progress.textContent = data.message || 'Updated. Restarting…'
    progress.hidden = false
    await wait(4000) // server is re-executing
    for (let i = 0; i < 30; i++) {
      try {
        if ((await fetch('/api/sync-state', { cache: 'no-store' })).ok) return location.reload()
      } catch {
        // still restarting
      }
      await wait(2000)
    }
    throw new Error('The app has not come back after updating. Start it again with run.py.')
  } catch (e) {
    error.textContent = e.message
    error.hidden = false
    progress.hidden = true
    busy(button, false)
    later.disabled = false
    $('span', button).textContent = 'Update now'
    dialog.oncancel = null
  }
}

// ------------------------------------------------------------------ Events

document.addEventListener('click', (event) => {
  const target = event.target.closest('button, a')

  // Close any open ⋯ menu that this click is not inside.
  for (const menu of $$('.menu:not([hidden])')) {
    if (!menu.parentElement.contains(event.target)) {
      menu.hidden = true
      $('[data-menu]', menu.parentElement).setAttribute('aria-expanded', 'false')
    }
  }
  if (!target) return
  const d = target.dataset

  if ('menu' in d) {
    const menu = target.nextElementSibling
    menu.hidden = !menu.hidden
    target.setAttribute('aria-expanded', String(!menu.hidden))
  } else if (d.action === 'sync') syncDevice(target)
  else if (d.action === 'sync-all') syncAll(target)
  else if (d.action === 'test') {
    target.closest('.menu').hidden = true
    testDevice(target)
  } else if (d.action === 'delete') {
    target.closest('.menu').hidden = true
    deleteDevice(target)
  } else if ('filterTab' in d) {
    const [group, state] = filterState(target)
    state.tab = d.filterTab
    applyFilters(group)
  } else if ('filterClear' in d) {
    const [group, state] = filterState(target)
    Object.assign(state, { tab: 'all', q: '', device: '' })
    applyFilters(group)
  } else if ('details' in d) {
    const details = target.closest('.what').nextElementSibling
    details.hidden = !details.hidden
    target.textContent = details.hidden ? 'Details' : 'Hide'
    target.setAttribute('aria-expanded', String(!details.hidden))
  } else if ('rawError' in d) {
    target.classList.toggle('open')
    target.title = target.classList.contains('open') ? 'Show less' : 'Show the full message'
  } else if ('themeToggle' in d) toggleTheme()
  else if ('reveal' in d) toggleReveal(target)
  else if ('test' in d) testSettings(target)
  else if ('serviceInstall' in d) installService(target)
  else if ('serviceRemove' in d) removeService(target)
  else if ('updateCheck' in d) checkUpdates(target)
  else if ('openUpdate' in d) openUpdateDialog()
  else if ('updateLater' in d) dismissUpdate()
  else if ('updateApply' in d) applyUpdate(target)
})

document.addEventListener('input', (event) => {
  const el = event.target
  if (el.matches('[data-filter-search]')) {
    const [group, state] = filterState(el)
    state.q = el.value
    applyFilters(group)
  }
})

document.addEventListener('change', (event) => {
  const el = event.target
  if (el.matches('[data-filter-device]')) {
    const [group, state] = filterState(el)
    state.device = el.value
    applyFilters(group)
  } else if (el.matches('[name=attendance_source]')) {
    const root = el.closest('[data-source-root]')
    root.classList.remove('source-direct', 'source-biotime', 'source-adms')
    root.classList.add(`source-${el.value}`)
  }
})

document.addEventListener('submit', (event) => {
  const form = event.target
  if (form.matches('[data-device-form]')) {
    event.preventDefault()
    saveDevice(form)
  } else if (form.matches('[data-settings-form]')) {
    event.preventDefault()
    saveSettings(form)
  }
})

// --------------------------------------------------------------------- Start

renderTimes()
applyAllFilters()
renderThemeButton()
matchMedia('(prefers-color-scheme: dark)').addEventListener('change', renderThemeButton)
showPendingToast()
pollState()
setInterval(pollState, 5000)
setInterval(() => renderTimes(), 30000)
loadUpdates()
loadService()
loadShiftTypes()
