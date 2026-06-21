<script lang="ts">
import { onMount, tick } from "svelte";

import I18nKey from "../i18n/i18nKey";
import { i18n } from "../i18n/translation";
import { getPostUrlBySlug } from "../utils/url-utils";

export let tags: string[] = [];
export let categories: string[] = [];
export let sortedPosts: Post[] = [];

const params = new URLSearchParams(window.location.search);
tags = params.has("tag") ? params.getAll("tag") : [];
categories = params.has("category") ? params.getAll("category") : [];
const uncategorized = params.get("uncategorized");

interface Post {
	slug: string;
	data: {
			title: string;
			tags: string[];
			category?: string | null;
			published: Date;
		};
	}

interface TimelineItem {
	post: Post;
	year: number;
	showYear: boolean;
}

interface ArchiveYearGroup {
	year: number;
	items: TimelineItem[];
}

let timelineItems: TimelineItem[] = [];
let archiveYearGroups: ArchiveYearGroup[] = [];
let filteredCount = 0;
let activeFilters: string[] = [];
let viewMode: "gui" | "list" = "gui";

function formatDate(date: Date) {
	return new Intl.DateTimeFormat("en", {
		month: "short",
		day: "2-digit",
	}).format(date);
}

function formatListDate(date: Date) {
	return new Intl.DateTimeFormat("en", {
		month: "2-digit",
		day: "2-digit",
	}).format(date);
}

function buildActiveFilters() {
	const filters: string[] = [];
	tags.forEach((tag) => filters.push(`#${tag}`));
	categories.forEach((category) => filters.push(category));
	if (uncategorized) filters.push(i18n(I18nKey.uncategorized));
	return filters;
}

const nodeVariants = [
	{ width: 29, space: 8, shift: -0.18, padding: 0.46, incomingY: -18, outgoingY: 19 },
	{ width: 35, space: 10, shift: 0.16, padding: 0.5, incomingY: -11, outgoingY: 25 },
	{ width: 27, space: 14, shift: -0.05, padding: 0.43, incomingY: -24, outgoingY: 13 },
	{ width: 33, space: 5.5, shift: 0.24, padding: 0.49, incomingY: -14, outgoingY: 22 },
	{ width: 38, space: 11, shift: -0.24, padding: 0.5, incomingY: -21, outgoingY: 16 },
	{ width: 26, space: 13, shift: 0.08, padding: 0.44, incomingY: -9, outgoingY: 27 },
];

const connectorVariants = [
	{ bend: 1.5 },
	{ bend: 1.3 },
	{ bend: 1.8 },
	{ bend: 1.6 },
	{ bend: 1.2 },
	{ bend: 1.7 },
];

function getNodeVariant(index: number) {
	return nodeVariants[index % nodeVariants.length];
}

function getConnectorVariant(index: number) {
	return connectorVariants[index % connectorVariants.length];
}

function getNodeStyle(index: number) {
	const variant = getNodeVariant(index);
	return [
		`--node-width: ${variant.width}%`,
		`--side-space: ${variant.space}%`,
		`--node-shift-y: ${variant.shift}rem`,
		`--node-padding-block: ${variant.padding}rem`,
	].join("; ");
}

const lineRevealMs = 210;
const nodeRevealOverlapMs = 55;
const nodeSettleMs = 45;
let chainNodes = new Map<number, HTMLElement>();
let flowElement: HTMLElement;
let connectorPaths: string[] = [];
let flowSize = { width: 100, height: 100 };
let connectorFrame = 0;
let revealedIndex = -1;
let visibleConnectorIndex = -1;
let revealTargetIndex = -1;
let chainRunning = false;
let revealRunId = 0;
let activeRevealRunId = 0;

function clampNumber(value: number, min: number, max: number) {
	return Math.min(max, Math.max(min, value));
}

function getSvgPoint(svgRect: DOMRect, x: number, y: number) {
	return {
		x: x - svgRect.left,
		y: y - svgRect.top,
	};
}

function getRenderedAnchor(node: HTMLElement, svgRect: DOMRect, index: number, isOutgoing: boolean) {
	const rect = node.getBoundingClientRect();
	const variant = getNodeVariant(index);
	const edgeInset = 10;
	const yOffset = isOutgoing ? variant.outgoingY : variant.incomingY;
	const x = index % 2 === 0 ? rect.right - edgeInset : rect.left + edgeInset;
	const y = clampNumber(rect.top + rect.height / 2 + yOffset, rect.top + 9, rect.bottom - 9);
	return getSvgPoint(svgRect, x, y);
}

function buildRenderedConnectorPath(index: number, item: HTMLElement, nextItem: HTMLElement) {
	const node = item.querySelector<HTMLElement>(".archive-node");
	const nextNode = nextItem.querySelector<HTMLElement>(".archive-node");
	if (!flowElement || !node || !nextNode) return "";

	const flowRect = flowElement.getBoundingClientRect();
	const start = getRenderedAnchor(node, flowRect, index, true);
	const end = getRenderedAnchor(nextNode, flowRect, index + 1, false);
	const variant = getConnectorVariant(index);
	const bend = (index % 2 === 0 ? variant.bend : -variant.bend) * (flowRect.width / 100);
	const controlX = (start.x + end.x) / 2 + bend;
	const controlY = (start.y + end.y) / 2 + (index % 2 === 0 ? -18 : 18);

	return `M ${start.x.toFixed(2)} ${start.y.toFixed(2)} Q ${controlX.toFixed(2)} ${controlY.toFixed(2)} ${end.x.toFixed(2)} ${end.y.toFixed(2)}`;
}

function updateConnectorPaths() {
	if (!flowElement) return;
	const rect = flowElement.getBoundingClientRect();
	flowSize = {
		width: Math.max(1, rect.width),
		height: Math.max(1, rect.height),
	};
	const items = Array.from(flowElement.querySelectorAll<HTMLElement>(".archive-item"));
	connectorPaths = items.map((item, index) => {
		const nextItem = items[index + 1];
		return nextItem ? buildRenderedConnectorPath(index, item, nextItem) : "";
	});
}

function scheduleConnectorUpdate() {
	if (typeof window === "undefined" || !flowElement) return;
	if (connectorFrame) return;
	connectorFrame = window.requestAnimationFrame(() => {
		connectorFrame = 0;
		updateConnectorPaths();
	});
}

function waitChainStep(duration: number) {
	return new Promise<void>((resolve) => {
		window.setTimeout(resolve, duration);
	});
}

function revealArchiveItem(_node?: HTMLElement, _isInitial = false) {
	scheduleConnectorUpdate();
}

function revealIncomingLine(index: number) {
	visibleConnectorIndex = Math.max(visibleConnectorIndex, index - 1);
	scheduleConnectorUpdate();
}

function revealInitialArchiveRange(index: number) {
	requestArchiveRevealUpTo(index);
}

async function runArchiveRevealQueue() {
	if (chainRunning) return;
	const runId = revealRunId;
	activeRevealRunId = runId;
	chainRunning = true;

	while (runId === revealRunId && revealedIndex < revealTargetIndex) {
		const nextIndex = revealedIndex + 1;
		const nextNode = chainNodes.get(nextIndex);
		if (!nextNode) break;

		if (nextIndex > 0) {
			revealIncomingLine(nextIndex);
			await waitChainStep(lineRevealMs - nodeRevealOverlapMs);
		}

		revealArchiveItem(nextNode);
		revealedIndex = nextIndex;
		await waitChainStep(nextIndex > 0 ? nodeRevealOverlapMs + nodeSettleMs : nodeSettleMs);
	}

	if (activeRevealRunId !== runId) return;

	chainRunning = false;
	if (runId === revealRunId && revealedIndex < revealTargetIndex) {
		void runArchiveRevealQueue();
	}
}

function requestArchiveRevealUpTo(index: number) {
	revealTargetIndex = Math.max(revealTargetIndex, index);
	void runArchiveRevealQueue();
}

function resetArchiveRevealState() {
	revealRunId += 1;
	activeRevealRunId = revealRunId;
	chainRunning = false;
	chainNodes = new Map<number, HTMLElement>();
	connectorPaths = [];
	revealedIndex = -1;
	visibleConnectorIndex = -1;
	revealTargetIndex = -1;
	flowSize = { width: 100, height: 100 };

	if (typeof window !== "undefined" && connectorFrame) {
		window.cancelAnimationFrame(connectorFrame);
		connectorFrame = 0;
	}
}

async function setArchiveMode(mode: "gui" | "list") {
	if (mode === viewMode) return;
	resetArchiveRevealState();
	viewMode = mode;
	await tick();
	if (mode === "gui") {
		scheduleConnectorUpdate();
	}
}

onMount(() => {
	scheduleConnectorUpdate();
	const resizeObserver = typeof ResizeObserver !== "undefined"
		? new ResizeObserver(scheduleConnectorUpdate)
		: null;

	if (resizeObserver && flowElement) {
		resizeObserver.observe(flowElement);
		flowElement.querySelectorAll(".archive-node").forEach((node) => {
			resizeObserver.observe(node);
		});
	}

	window.addEventListener("resize", scheduleConnectorUpdate, { passive: true });
	window.addEventListener("load", scheduleConnectorUpdate, { once: true });

	return () => {
		if (connectorFrame) window.cancelAnimationFrame(connectorFrame);
		resizeObserver?.disconnect();
		window.removeEventListener("resize", scheduleConnectorUpdate);
		window.removeEventListener("load", scheduleConnectorUpdate);
	};
});

function observeArchiveItem(node: HTMLElement, index: number) {
	chainNodes.set(index, node);
	if (index > 0) scheduleConnectorUpdate();

	if (index <= revealedIndex) {
		revealArchiveItem(node, true);
		if (index > 0) {
			visibleConnectorIndex = Math.max(visibleConnectorIndex, index - 1);
		}
		return {
			destroy() {
				chainNodes.delete(index);
			},
		};
	}

	if (typeof window === "undefined" || !("IntersectionObserver" in window)) {
		revealInitialArchiveRange(index);
		return {};
	}

	const rect = node.getBoundingClientRect();
	const isInitialVisible = rect.top < window.innerHeight * 0.9;
	if (isInitialVisible) {
		revealInitialArchiveRange(index);
		return {
			destroy() {
				chainNodes.delete(index);
			},
		};
	}

	let fallbackTimer = window.setTimeout(() => {
		if (node.classList.contains("is-node-visible")) return;
		const latestRect = node.getBoundingClientRect();
		if (latestRect.top < window.innerHeight * 1.08) {
			requestArchiveRevealUpTo(index);
			observer.unobserve(node);
		}
	}, 900);

	const observer = new IntersectionObserver(
		(entries) => {
			entries.forEach((entry) => {
				if (!entry.isIntersecting) return;
				window.clearTimeout(fallbackTimer);
				requestArchiveRevealUpTo(index);
				observer.unobserve(node);
			});
		},
		{ root: null, rootMargin: "0px 0px -8% 0px", threshold: 0.08 },
	);

	observer.observe(node);
	return {
		destroy() {
			window.clearTimeout(fallbackTimer);
			observer.disconnect();
			chainNodes.delete(index);
		},
	};
}

$: {
	let filteredPosts: Post[] = sortedPosts;
	activeFilters = buildActiveFilters();

	if (tags.length > 0) {
		filteredPosts = filteredPosts.filter(
			(post) =>
				Array.isArray(post.data.tags) &&
				post.data.tags.some((tag) => tags.includes(tag)),
		);
	}

	if (categories.length > 0) {
		filteredPosts = filteredPosts.filter(
			(post) => post.data.category && categories.includes(post.data.category),
		);
	}

	if (uncategorized) {
		filteredPosts = filteredPosts.filter((post) => !post.data.category);
	}

	const seenYears = new Set<number>();
	timelineItems = filteredPosts.map((post) => {
		const year = post.data.published.getFullYear();
		const showYear = !seenYears.has(year);
		seenYears.add(year);
		return { post, year, showYear };
	});

	const grouped = new Map<number, TimelineItem[]>();
	timelineItems.forEach((item) => {
		const items = grouped.get(item.year) ?? [];
		items.push(item);
		grouped.set(item.year, items);
	});
	archiveYearGroups = Array.from(grouped.entries()).map(([year, items]) => ({ year, items }));

	filteredCount = filteredPosts.length;
}
</script>

<div class="archive-shell">
	<section class="archive-summary">
		<div>
			<span>Archive</span>
			<strong>{filteredCount}</strong>
		</div>

		<div class="archive-summary-actions">
			<div class="archive-view-switch" aria-label="Archive view mode">
				<button type="button" class={viewMode === "gui" ? "is-active" : ""} on:click={() => setArchiveMode("gui")}>GUI</button>
				<button type="button" class={viewMode === "list" ? "is-active" : ""} on:click={() => setArchiveMode("list")}>List</button>
			</div>

			{#if activeFilters.length > 0}
				<div class="active-filters" aria-label="Active filters">
					{#each activeFilters as filter}
						<span>{filter}</span>
					{/each}
					<a href="/archive/">Clear</a>
				</div>
			{/if}
		</div>
	</section>

	{#if timelineItems.length === 0}
		<section class="archive-empty">
			<h2>No posts found</h2>
			<p>현재 필터 조건에 맞는 글이 없습니다.</p>
		</section>
	{:else if viewMode === "gui"}
		<section bind:this={flowElement} class="archive-flow" aria-label="Archive timeline">
			<svg class="archive-link-layer" viewBox={`0 0 ${flowSize.width} ${flowSize.height}`} preserveAspectRatio="none" aria-hidden="true">
				{#each timelineItems.slice(0, -1) as _, index}
					<path class={`archive-link-path link-glow ${index <= visibleConnectorIndex ? "is-visible" : ""}`} pathLength="1" d={connectorPaths[index] || ""}></path>
					<path class={`archive-link-path link-core ${index <= visibleConnectorIndex ? "is-visible" : ""}`} pathLength="1" d={connectorPaths[index] || ""}></path>
				{/each}
			</svg>

			{#each timelineItems as item, index}
				<article use:observeArchiveItem={index} class={`archive-item ${index % 2 === 0 ? "left" : "right"} ${item.showYear ? "new-year" : ""} ${index <= revealedIndex ? "is-node-visible" : ""}`} style={getNodeStyle(index)}>
					<a href={getPostUrlBySlug(item.post.slug)} aria-label={item.post.data.title} class="archive-node">
						<time>{formatDate(item.post.data.published)}</time>
						<h2>{item.post.data.title}</h2>
						<span>{item.showYear ? item.year : item.post.data.category || "Note"}</span>
					</a>
				</article>
			{/each}
		</section>
	{:else}
		<section class="archive-list" aria-label="Archive list">
			{#each archiveYearGroups as group}
				<section class="archive-list-year">
					<h2>{group.year}</h2>
					<div class="archive-list-items">
						{#each group.items as item}
							<a href={getPostUrlBySlug(item.post.slug)} class="archive-list-row" aria-label={item.post.data.title}>
								<time>{formatListDate(item.post.data.published)}</time>
								<span class="archive-list-title">{item.post.data.title}</span>
								<span class="archive-list-category">{item.post.data.category || "Note"}</span>
							</a>
						{/each}
					</div>
				</section>
			{/each}
		</section>
	{/if}
</div>

<style>
	.archive-shell {
		position: relative;
		isolation: isolate;
		margin-bottom: 2.25rem;
		padding: 0.2rem 0 1.2rem;
	}

	.archive-shell::before {
		content: "";
		position: absolute;
		inset: -8rem -4rem -5rem;
		z-index: -1;
		background:
			radial-gradient(circle at 16% 4%, rgba(196, 123, 255, 0.16), transparent 18rem),
			radial-gradient(circle at 82% 36%, rgba(176, 92, 255, 0.12), transparent 23rem),
			radial-gradient(circle at 50% 100%, rgba(218, 178, 255, 0.07), transparent 22rem);
		pointer-events: none;
	}

	.archive-summary {
		display: flex;
		align-items: center;
		justify-content: space-between;
		gap: 1rem;
		margin-bottom: 1.2rem;
		padding: 0 0.15rem;
		color: rgb(232 216 255 / 0.52);
		font-size: 0.76rem;
		font-weight: 830;
	}

	.archive-summary-actions {
		display: flex;
		align-items: center;
		justify-content: flex-end;
		gap: 0.65rem;
		min-width: 0;
	}

	.archive-summary > div:first-child {
		display: inline-flex;
		align-items: baseline;
		gap: 0.5rem;
	}

	.archive-summary strong {
		color: rgb(224 188 255 / 0.92);
		font-size: 0.95rem;
		font-weight: 950;
	}

	.archive-view-switch {
		display: inline-flex;
		align-items: center;
		gap: 0.18rem;
		border: 1px solid rgba(198, 132, 255, 0.18);
		border-radius: 999rem;
		padding: 0.18rem;
		background:
			linear-gradient(135deg, rgba(255, 255, 255, 0.055), rgba(198, 132, 255, 0.07)),
			rgba(7, 4, 13, 0.78);
		box-shadow:
			inset 0 1px 0 rgba(255, 255, 255, 0.035),
			0 0 1.6rem rgba(198, 132, 255, 0.08);
	}

	.archive-view-switch button {
		border: 0;
		border-radius: 999rem;
		padding: 0.28rem 0.68rem;
		color: rgb(232 216 255 / 0.56);
		background: transparent;
		font-size: 0.72rem;
		font-weight: 900;
		line-height: 1;
		cursor: pointer;
		transition:
			color 0.16s ease,
			background 0.16s ease,
			box-shadow 0.16s ease;
	}

	.archive-view-switch button:hover {
		color: rgb(249 238 255 / 0.88);
	}

	.archive-view-switch button.is-active {
		color: rgb(255 255 255 / 0.95);
		background:
			linear-gradient(135deg, rgba(255, 255, 255, 0.14), rgba(198, 132, 255, 0.24)),
			rgba(98, 44, 151, 0.48);
		box-shadow:
			0 0 0 1px rgba(245, 226, 255, 0.1),
			0 0 1.2rem rgba(198, 132, 255, 0.28);
	}

	.active-filters {
		display: flex;
		flex-wrap: wrap;
		justify-content: flex-end;
		gap: 0.42rem;
	}

	.active-filters span,
	.active-filters a {
		border: 1px solid rgba(198, 132, 255, 0.14);
		border-radius: 999rem;
		padding: 0.22rem 0.46rem;
		color: rgb(232 216 255 / 0.68);
		background: rgba(198, 132, 255, 0.045);
		font-size: 0.72rem;
		font-weight: 790;
		text-decoration: none;
	}

	.active-filters a {
		color: var(--primary);
	}

	.archive-flow {
		--flow-gap: 2.35rem;
		position: relative;
		display: flex;
		flex-direction: column;
		gap: var(--flow-gap);
		isolation: isolate;
		overflow: visible;
		padding: 0.8rem 0 0.6rem;
	}

	.archive-item {
		--node-width: 30%;
		--side-space: 8.5%;
		--node-shift-y: 0rem;
		--node-padding-block: 0.48rem;
		--node-padding-inline: 0.78rem;
		position: relative;
		z-index: 1;
		min-height: 4.25rem;
	}

	.archive-item.new-year:not(:first-child) {
		margin-top: 0;
	}

	.archive-link-layer {
		position: absolute;
		inset: 0;
		z-index: 0;
		width: 100%;
		height: 100%;
		overflow: visible;
		pointer-events: none;
	}

	.archive-link-path {
		fill: none;
		stroke-dasharray: 1;
		stroke-dashoffset: 1;
		stroke-linecap: round;
		stroke-linejoin: round;
		vector-effect: non-scaling-stroke;
		opacity: 0;
		transition:
			opacity 0.12s ease,
			stroke-dashoffset 0.21s cubic-bezier(0.18, 0.82, 0.16, 1);
	}

	.archive-link-path.link-glow {
		stroke: rgba(214, 164, 255, 0.52);
		stroke-width: 6.4;
		opacity: 0;
		filter:
			drop-shadow(0 0 12px rgba(232, 202, 255, 0.42))
			drop-shadow(0 0 28px rgba(172, 92, 255, 0.68))
			drop-shadow(0 0 54px rgba(132, 62, 228, 0.36));
	}

	.archive-link-path.link-core {
		stroke: rgba(246, 229, 255, 0.98);
		stroke-width: 1.7;
		opacity: 0;
		filter:
			drop-shadow(0 0 8px rgba(232, 202, 255, 0.92))
			drop-shadow(0 0 18px rgba(198, 132, 255, 0.7))
			drop-shadow(0 0 32px rgba(172, 92, 255, 0.44));
	}

	.archive-node {
		position: relative;
		z-index: 5;
		isolation: isolate;
		display: flex;
		width: var(--node-width);
		min-width: 0;
		flex-direction: column;
		justify-content: center;
		padding: var(--node-padding-block) 0 calc(var(--node-padding-block) + 0.04rem) var(--node-padding-inline);
		color: inherit;
		text-decoration: none;
		opacity: 0;
		visibility: hidden;
		pointer-events: none;
		background:
			linear-gradient(270deg, rgba(198, 132, 255, 0.12), rgba(198, 132, 255, 0.03) 58%, transparent 96%),
			linear-gradient(180deg, rgba(255, 255, 255, 0.035), transparent 68%),
			rgb(5 3 10);
		border-right: 2px solid rgba(226, 190, 255, 0.76);
		border-radius: 1rem 0.25rem 0.28rem 0.7rem;
		box-shadow:
			12px 0 30px -25px rgba(198, 132, 255, 0.95),
			inset 0 1px 0 rgba(255, 255, 255, 0.025);
		transform: translateY(var(--node-shift-y));
		transform-origin: right center;
		transition:
			opacity 0.16s cubic-bezier(0.16, 0.84, 0.2, 1),
			transform 0.18s ease,
			background 0.18s ease,
			border-color 0.18s ease,
			box-shadow 0.18s ease;
		will-change: opacity;
	}

	.archive-node::before {
		content: "";
		position: absolute;
		right: -2px;
		top: 0.54rem;
		bottom: 0.54rem;
		z-index: 6;
		width: 2px;
		background: linear-gradient(
			180deg,
			transparent,
			rgba(242, 222, 255, 0.62) 24%,
			rgba(198, 132, 255, 0.7) 50%,
			rgba(242, 222, 255, 0.62) 76%,
			transparent
		);
		box-shadow:
			0 0 0.5rem rgba(232, 202, 255, 0.5),
			0 0 1rem rgba(198, 132, 255, 0.38);
		pointer-events: none;
	}

	.archive-node::after {
		content: "";
		position: absolute;
		inset: 0;
		z-index: -1;
		border-radius: inherit;
		background: rgb(5 3 10);
		box-shadow:
			inset 0 0 0 1px rgb(5 3 10),
			0 0 0.58rem rgba(4, 3, 9, 0.5);
		pointer-events: none;
	}

	.archive-node > * {
		position: relative;
		z-index: 2;
	}

	.archive-item.left .archive-node {
		margin-left: var(--side-space);
		margin-right: auto;
	}

	.archive-item.right .archive-node {
		align-items: flex-end;
		margin-left: auto;
		margin-right: var(--side-space);
		padding: var(--node-padding-block) var(--node-padding-inline) calc(var(--node-padding-block) + 0.04rem) 0;
		border-right: 0;
		border-left: 2px solid rgba(226, 190, 255, 0.76);
		border-radius: 0.25rem 1rem 0.7rem 0.28rem;
		text-align: right;
		background:
			linear-gradient(90deg, rgba(198, 132, 255, 0.12), rgba(198, 132, 255, 0.03) 58%, transparent 96%),
			linear-gradient(180deg, rgba(255, 255, 255, 0.035), transparent 68%),
			rgb(5 3 10);
		box-shadow:
			-12px 0 30px -25px rgba(198, 132, 255, 0.95),
			inset 0 1px 0 rgba(255, 255, 255, 0.025);
		transform-origin: left center;
	}

	.archive-item.right .archive-node::before {
		right: auto;
		left: -2px;
	}

	.archive-node:hover {
		transform: translateY(calc(var(--node-shift-y) - 2px));
		border-color: rgba(242, 222, 255, 0.98);
		background:
			linear-gradient(270deg, rgba(198, 132, 255, 0.18), rgba(198, 132, 255, 0.045) 62%, transparent 98%),
			linear-gradient(180deg, rgba(255, 255, 255, 0.045), transparent 70%);
		box-shadow:
			12px 0 32px -22px rgba(198, 132, 255, 0.95),
			0 0 30px rgba(172, 92, 255, 0.11);
	}

	.archive-item.right .archive-node:hover {
		background:
			linear-gradient(90deg, rgba(198, 132, 255, 0.18), rgba(198, 132, 255, 0.045) 62%, transparent 98%),
			linear-gradient(180deg, rgba(255, 255, 255, 0.045), transparent 70%);
		box-shadow:
			-12px 0 32px -22px rgba(198, 132, 255, 0.95),
			0 0 30px rgba(172, 92, 255, 0.11);
	}

	.archive-node time,
	.archive-node span {
		color: rgb(232 216 255 / 0.48);
		font-size: 0.68rem;
		font-weight: 850;
		line-height: 1.2;
	}

	.archive-node span {
		margin-top: 0.22rem;
		color: var(--primary);
	}

	.archive-node h2 {
		display: -webkit-box;
		margin: 0.22rem 0 0;
		overflow: hidden;
		color: rgb(255 255 255 / 0.9);
		font-size: 0.94rem;
		font-weight: 880;
		line-height: 1.34;
		letter-spacing: 0;
		-webkit-box-orient: vertical;
		-webkit-line-clamp: 2;
	}

	.archive-link-path.is-visible {
		stroke-dashoffset: 0;
	}

	.archive-link-path.link-glow.is-visible {
		opacity: 0.52;
	}

	.archive-link-path.link-core.is-visible {
		opacity: 1;
	}

	.archive-item.is-node-visible .archive-node {
		opacity: 1;
		visibility: visible;
		pointer-events: auto;
	}

	.archive-list {
		position: relative;
		display: flex;
		flex-direction: column;
		gap: 1.1rem;
		padding-top: 0.45rem;
	}

	.archive-list::before {
		content: "";
		position: absolute;
		top: 0.75rem;
		bottom: 0.35rem;
		left: 0.28rem;
		width: 1px;
		background: linear-gradient(180deg, rgba(232, 202, 255, 0.48), rgba(198, 132, 255, 0.16), transparent);
		box-shadow: 0 0 1.4rem rgba(198, 132, 255, 0.2);
		pointer-events: none;
	}

	.archive-list-year {
		position: relative;
		display: grid;
		grid-template-columns: minmax(4.2rem, 5.6rem) minmax(0, 1fr);
		gap: clamp(0.9rem, 2vw, 1.5rem);
	}

	.archive-list-year h2 {
		position: sticky;
		top: 5.5rem;
		align-self: start;
		margin: 0;
		color: rgb(245 226 255 / 0.94);
		font-size: clamp(1.25rem, 3vw, 1.9rem);
		font-weight: 950;
		letter-spacing: 0;
		text-shadow:
			0 0 1.2rem rgba(232, 202, 255, 0.28),
			0 0 3rem rgba(172, 92, 255, 0.28);
	}

	.archive-list-items {
		display: flex;
		flex-direction: column;
		border-top: 1px solid rgba(198, 132, 255, 0.13);
	}

	.archive-list-row {
		position: relative;
		display: grid;
		grid-template-columns: 5rem minmax(0, 1fr) auto;
		align-items: center;
		gap: 1rem;
		min-height: 4.15rem;
		border-bottom: 1px solid rgba(198, 132, 255, 0.11);
		padding: 0.88rem 0.35rem 0.88rem 0;
		color: inherit;
		text-decoration: none;
		background: linear-gradient(90deg, rgba(198, 132, 255, 0.024), transparent 72%);
		transition:
			background 0.16s ease,
			border-color 0.16s ease,
			transform 0.16s ease;
	}

	.archive-list-row::before {
		content: "";
		position: absolute;
		left: -1.28rem;
		top: 50%;
		width: 0.42rem;
		height: 0.42rem;
		border-radius: 999rem;
		background: rgba(232, 202, 255, 0.76);
		box-shadow:
			0 0 0 0.24rem rgba(198, 132, 255, 0.1),
			0 0 1.2rem rgba(198, 132, 255, 0.44);
		transform: translateY(-50%);
	}

	.archive-list-row:hover {
		border-color: rgba(198, 132, 255, 0.25);
		background: linear-gradient(90deg, rgba(198, 132, 255, 0.07), transparent 72%);
		transform: translateX(2px);
	}

	.archive-list-row time {
		color: rgb(232 216 255 / 0.5);
		font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
		font-size: 0.78rem;
		font-weight: 850;
	}

	.archive-list-title {
		overflow: hidden;
		color: rgb(255 255 255 / 0.9);
		font-size: clamp(0.98rem, 1.5vw, 1.08rem);
		font-weight: 880;
		line-height: 1.35;
		text-overflow: ellipsis;
		white-space: nowrap;
	}

	.archive-list-category {
		border: 1px solid rgba(198, 132, 255, 0.16);
		border-radius: 999rem;
		padding: 0.22rem 0.52rem;
		color: var(--primary);
		background: rgba(198, 132, 255, 0.055);
		font-size: 0.72rem;
		font-weight: 860;
		white-space: nowrap;
	}

	.archive-empty {
		border-left: 1px solid rgba(198, 132, 255, 0.24);
		padding: 0.75rem 0 0.75rem 1rem;
	}

	.archive-empty h2 {
		margin: 0;
		color: rgb(255 255 255 / 0.9);
		font-size: 1rem;
		font-weight: 900;
		letter-spacing: 0;
	}

	.archive-empty p {
		margin: 0.22rem 0 0;
		color: rgb(232 216 255 / 0.58);
		font-size: 0.88rem;
	}

	@media (max-width: 720px) {
		.archive-summary {
			align-items: flex-start;
			flex-direction: column;
		}

		.archive-summary-actions {
			width: 100%;
			align-items: flex-start;
			flex-direction: column;
			justify-content: flex-start;
		}

		.archive-flow {
			gap: 0.78rem;
			padding: 0;
		}

		.archive-item {
			--node-shift-y: 0rem;
			--node-padding-block: 0.62rem;
			--node-padding-inline: 0.82rem;
			min-height: auto;
		}

		.archive-link-layer {
			display: none;
		}

		.archive-node,
		.archive-item.left .archive-node,
		.archive-item.right .archive-node {
			align-items: flex-start;
			width: 100%;
			margin-left: 0;
			margin-right: 0;
			padding: 0.62rem 0 0.62rem 0.82rem;
			border-right: 0;
			border-left: 2px solid rgba(226, 190, 255, 0.76);
			text-align: left;
			background: linear-gradient(90deg, rgba(198, 132, 255, 0.095), transparent 92%);
			box-shadow: -10px 0 28px -26px rgba(198, 132, 255, 0.9);
			transform: none;
		}

		.archive-list::before {
			left: 0.18rem;
		}

		.archive-list-year {
			grid-template-columns: 1fr;
			gap: 0.4rem;
			padding-left: 0.9rem;
		}

		.archive-list-year h2 {
			position: relative;
			top: auto;
			font-size: 1.2rem;
		}

		.archive-list-row {
			grid-template-columns: 4.2rem minmax(0, 1fr);
			gap: 0.7rem;
		}

		.archive-list-category {
			grid-column: 2;
			justify-self: start;
		}
	}
</style>
