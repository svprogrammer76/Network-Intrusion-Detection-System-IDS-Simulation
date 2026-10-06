const totalEventsEl = document.getElementById('total-events');
const blockedEventsEl = document.getElementById('blocked-events');
const criticalEventsEl = document.getElementById('critical-events');
const riskLevelEl = document.getElementById('risk-level');
const attackBreakdownEl = document.getElementById('attack-breakdown');
const severityBreakdownEl = document.getElementById('severity-breakdown');
const eventsBodyEl = document.getElementById('events-body');
const refreshButton = document.getElementById('refresh-events');

function renderBreakdown(list, target) {
  if (!target) return;
  target.innerHTML = '';

  Object.entries(list).forEach(([key, value]) => {
    const item = document.createElement('li');
    item.innerHTML = `<span>${key}</span><strong>${value}</strong>`;
    target.appendChild(item);
  });
}

function renderEvents(events) {
  eventsBodyEl.innerHTML = '';

  events.forEach((event) => {
    const row = document.createElement('tr');
    row.innerHTML = `
      <td>${event.timestamp}</td>
      <td>${event.signature}</td>
      <td>${event.source_ip}</td>
      <td>${event.target}</td>
      <td><span class="badge ${event.severity}">${event.severity}</span></td>
      <td>${event.status}</td>
    `;
    eventsBodyEl.appendChild(row);
  });
}

async function loadSummary() {
  const res = await fetch('/api/summary');
  const summary = await res.json();

  totalEventsEl.textContent = summary.total_events;
  blockedEventsEl.textContent = summary.blocked_events;
  criticalEventsEl.textContent = summary.critical_events;
  riskLevelEl.textContent = summary.risk_level;

  renderBreakdown(summary.top_attack_types, attackBreakdownEl);
  renderBreakdown(summary.severity_breakdown, severityBreakdownEl);
}

async function loadEvents() {
  const res = await fetch('/api/events');
  const payload = await res.json();
  renderEvents(payload.events);
}

async function simulateScenario(scenario) {
  const res = await fetch(`/api/simulate?scenario=${scenario}&count=10`);
  const payload = await res.json();
  const { summary } = payload;

  totalEventsEl.textContent = summary.total_events;
  blockedEventsEl.textContent = summary.blocked_events;
  criticalEventsEl.textContent = summary.critical_events;
  riskLevelEl.textContent = summary.risk_level;

  renderBreakdown(summary.top_attack_types, attackBreakdownEl);
  renderBreakdown(summary.severity_breakdown, severityBreakdownEl);
  await loadEvents();
}

document.querySelectorAll('.simulate').forEach((button) => {
  button.addEventListener('click', () => simulateScenario(button.dataset.scenario));
});

refreshButton.addEventListener('click', async () => {
  await loadSummary();
  await loadEvents();
});

loadSummary();
loadEvents();
