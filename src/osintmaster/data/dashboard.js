(() => {
  const query = document.getElementById("query");
  const filter = document.getElementById("status-filter");
  const cards = Array.from(document.querySelectorAll(".result-card"));
  const count = document.getElementById("visible-count");
  const empty = document.getElementById("empty-results");

  function visible(status, selected) {
    if (selected === "all") return true;
    if (selected === "active") return status !== "NOT_FOUND";
    if (selected === "unresolved") return ["UNKNOWN", "BLOCKED", "AUTH_REQUIRED", "ERROR", "RATE_LIMITED"].includes(status);
    return status === selected;
  }

  function update() {
    const term = query.value.trim().toLocaleLowerCase();
    let shown = 0;
    for (const card of cards) {
      const match = visible(card.dataset.status, filter.value)
        && card.textContent.toLocaleLowerCase().includes(term);
      card.hidden = !match;
      if (match) shown += 1;
    }
    count.textContent = shown + " of " + cards.length + " checks shown";
    empty.hidden = shown !== 0;
  }

  query.addEventListener("input", update);
  filter.addEventListener("change", update);
  update();

  const graphElement = document.getElementById("graph-data");
  if (!graphElement || !graphElement.textContent.trim()) return;
  const graph = JSON.parse(graphElement.textContent);
  const svg = document.getElementById("graph-svg");
  const graphQuery = document.getElementById("graph-query");
  const graphType = document.getElementById("graph-type");
  const detail = document.getElementById("graph-detail");
  const note = document.querySelector(".graph-note");
  const namespace = "http://www.w3.org/2000/svg";
  const colors = {
    USERNAME: "#57d9e9", PROFILE: "#5de0a9", URL: "#f8c76c",
    DOMAIN: "#b697ff", EMAIL: "#ff829b", IP_ADDRESS: "#80aaff",
    PERSON_NAME: "#f8a9d0", LOCATION: "#c1e18b", IMAGE_HASH: "#f7bb8a"
  };

  for (const type of [...new Set(graph.nodes.map(node => node.type))].sort()) {
    const option = document.createElement("option");
    option.value = type;
    option.textContent = type.replaceAll("_", " ");
    graphType.appendChild(option);
  }

  function element(name, attributes = {}) {
    const node = document.createElementNS(namespace, name);
    for (const [key, value] of Object.entries(attributes)) node.setAttribute(key, String(value));
    return node;
  }

  function nodeGlyph(node, point, size) {
    const common = {fill: colors[node.type] || "#9aaec5", class: "graph-node",
      tabindex: 0, "data-id": node.id};
    if (node.type === "EMAIL") {
      const points = [
        [point.x - size, point.y], [point.x - size / 2, point.y - size],
        [point.x + size / 2, point.y - size], [point.x + size, point.y],
        [point.x + size / 2, point.y + size], [point.x - size / 2, point.y + size]
      ].map(pair => pair.join(",")).join(" ");
      return element("polygon", {...common, points});
    }
    if (["USERNAME", "DOMAIN", "IP_ADDRESS", "URL", "IMAGE", "IMAGE_HASH"].includes(node.type)) {
      const width = size * (node.type === "USERNAME" ? 2.5 : 2.1);
      return element("rect", {...common, x: point.x - width / 2,
        y: point.y - size, width, height: size * 2,
        rx: node.type === "USERNAME" ? size : 3});
    }
    return element("circle", {...common, cx: point.x, cy: point.y, r: size});
  }

  function inspect(node) {
    for (const circle of svg.querySelectorAll(".graph-node")) {
      circle.classList.toggle("selected", circle.dataset.id === node.id);
    }
    detail.replaceChildren();
    const title = document.createElement("strong");
    title.textContent = node.type.replaceAll("_", " ") + " · " + node.value;
    detail.appendChild(title);
    const meta = document.createElement("p");
    meta.textContent = (node.first_seen ? "First observed: " + node.first_seen + " · " : "")
      + (node.last_seen ? "Last observed: " + node.last_seen + " · " : "")
      + node.observations + " observation(s)";
    detail.appendChild(meta);
    if (node.attributes && Object.keys(node.attributes).length) {
      const attributes = document.createElement("p");
      attributes.textContent = Object.entries(node.attributes)
        .map(([key, value]) => key + ": " + String(value)).join(" · ");
      detail.appendChild(attributes);
    }
    const observations = (graph.observations || [])
      .filter(item => item.entity_id === node.id)
      .sort((a, b) => String(b.observed_at).localeCompare(String(a.observed_at)));
    if (observations.length) {
      const heading = document.createElement("strong");
      heading.textContent = "Observations";
      detail.appendChild(heading);
      const history = document.createElement("ul");
      for (const item of observations.slice(0, 20)) {
        const line = document.createElement("li");
        const value = typeof item.value === "string" ? item.value : JSON.stringify(item.value);
        line.textContent = item.property + " · " + item.state + " · " + value
          + " · " + item.provider + " · " + item.observed_at;
        for (const id of item.evidence_ids || []) {
          const proof = (graph.evidence || []).find(record => record.id === id);
          if (!proof || !proof.source_url || !/^https?:\/\//.test(proof.source_url)) continue;
          const source = document.createElement("a");
          source.href = proof.source_url;
          source.textContent = " source";
          source.target = "_blank";
          source.rel = "noopener noreferrer";
          line.appendChild(source);
        }
        history.appendChild(line);
      }
      detail.appendChild(history);
    }
    const related = graph.edges.filter(edge => edge.source === node.id || edge.target === node.id);
    if (!related.length) return;
    const list = document.createElement("ul");
    for (const edge of related.slice(0, 20)) {
      const otherId = edge.source === node.id ? edge.target : edge.source;
      const other = graph.nodes.find(item => item.id === otherId);
      const line = document.createElement("li");
      line.textContent = edge.type.replaceAll("_", " ") + " → "
        + (other ? other.value : otherId) + " · " + edge.provider
        + (edge.score == null ? " · " + (edge.strength || "observed")
          : " · evidence score " + edge.score + "/100");
      if (edge.source_url && /^https?:\/\//.test(edge.source_url)) {
        const source = document.createElement("a");
        source.href = edge.source_url;
        source.textContent = " source";
        source.target = "_blank";
        source.rel = "noopener noreferrer";
        line.appendChild(source);
      }
      if (edge.evidence && edge.evidence.length) {
        const proof = document.createElement("small");
        proof.textContent = " · " + edge.evidence.map(item => item.type + ": " + item.value).join("; ");
        line.appendChild(proof);
      }
      list.appendChild(line);
    }
    detail.appendChild(list);
  }

  function drawGraph() {
    const term = graphQuery.value.trim().toLocaleLowerCase();
    const selectedType = graphType.value;
    const matching = graph.nodes.filter(node =>
      (selectedType === "all" || node.type === selectedType)
      && (!term || (node.type + " " + node.value).toLocaleLowerCase().includes(term))
    );
    const nodes = matching.slice(0, 160);
    note.textContent = "Showing " + nodes.length + " of " + matching.length
      + " matching entities. Lines show observed or claimed relationships.";
    svg.replaceChildren();
    if (!nodes.length) return;
    const positions = new Map();
    const centeredRoot = selectedType === "all" && !term;
    const perimeterCount = nodes.length - (centeredRoot ? 1 : 0);
    const ringCount = Math.max(1, Math.ceil(perimeterCount / 20));
    const perRing = Math.ceil(perimeterCount / ringCount);
    nodes.forEach((node, index) => {
      if (index === 0 && centeredRoot) {
        positions.set(node.id, {x: 500, y: 310});
        return;
      }
      const offset = index - (centeredRoot ? 1 : 0);
      const ring = Math.floor(offset / perRing);
      const slot = offset % perRing;
      const count = Math.min(perRing, perimeterCount - ring * perRing);
      const angle = (slot / count) * Math.PI * 2 + ring * .38 - Math.PI / 2;
      const radiusX = ringCount === 1 ? 340 : 145 + ring * 65;
      const radiusY = ringCount === 1 ? 220 : 100 + ring * 36;
      positions.set(node.id, {
        x: 500 + Math.cos(angle) * Math.min(420, radiusX),
        y: 310 + Math.sin(angle) * Math.min(265, radiusY)
      });
    });
    for (const edge of graph.edges) {
      const from = positions.get(edge.source);
      const to = positions.get(edge.target);
      if (!from || !to) continue;
      svg.appendChild(element("line", {
        x1: from.x, y1: from.y, x2: to.x, y2: to.y, class: "graph-edge",
        "stroke-dasharray": edge.strength === "hypothesis" ? "2 6"
          : edge.strength === "derived" ? "8 5" : "none"
      }));
    }
    nodes.forEach((node, index) => {
      const point = positions.get(node.id);
      const circle = nodeGlyph(node, point, index === 0 ? 13 : 8);
      const tooltip = element("title");
      tooltip.textContent = node.type + ": " + node.value;
      circle.appendChild(tooltip);
      circle.addEventListener("click", () => inspect(node));
      circle.addEventListener("keydown", event => {
        if (event.key === "Enter" || event.key === " ") inspect(node);
      });
      svg.appendChild(circle);
      if (index === 0 || (index < 8 && nodes.length < 30)) {
        const label = element("text", {
          x: point.x + 13, y: point.y - 10, class: "graph-label"
        });
        label.textContent = node.value.length > 24 ? node.value.slice(0, 24) + "…" : node.value;
        svg.appendChild(label);
      }
    });
  }

  graphQuery.addEventListener("input", drawGraph);
  graphType.addEventListener("change", drawGraph);
  drawGraph();
})();
