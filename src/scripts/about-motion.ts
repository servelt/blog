type ProfileLayout = {
	top: number;
	width: number;
	height: number;
	padding: number;
	paddingTop: number;
	avatar: number;
	name: number;
	gap: number;
	copyWidth: number;
};

let cleanupAboutMotion: (() => void) | undefined;

export function initAboutMotion() {
	cleanupAboutMotion?.();
	cleanupAboutMotion = undefined;

	const root = document.documentElement;
	const page = document.querySelector<HTMLElement>(".about-page");
	const track = page?.querySelector<HTMLElement>(".about-scroll-track");
	const mainbox = page?.querySelector<HTMLElement>(".about-mainbox");
	const liveStack = page?.querySelector<HTMLElement>(".about-live-stack");
	if (!page || !track || !mainbox || !liveStack) return;

	const media = window.matchMedia("(prefers-reduced-motion: reduce)");
	const items = Array.from(
		liveStack.querySelectorAll<HTMLElement>(
			".about-stats, .about-intro-card, .about-timeline-section, .about-achievements",
		),
	);
	const properties = new Set<string>();
	let expanded: ProfileLayout;
	let compact: ProfileLayout;
	let distance = 1;
	let narrow = false;
	let active = false;
	let disposed = false;
	let frame = 0;
	let measured = false;
	let targetRaw = 0;
	let displayedRaw = 0;
	let lastFrameAt = 0;
	const scrubResponse = 115;
	const maxRawStep = 0.04;

	const clamp = (value: number, min = 0, max = 1) =>
		Math.min(max, Math.max(min, value));
	const ease = (value: number) => 1 - (1 - value) ** 3;
	const smooth = (value: number) => value * value * (3 - 2 * value);
	const set = (name: string, value: string) => {
		properties.add(name);
		page.style.setProperty(name, value);
	};
	const pixel = (name: string, value: number) =>
		set(name, `${value.toFixed(2)}px`);
	const applyLayout = (layout: ProfileLayout) => {
		pixel("--about-main-top", layout.top);
		pixel("--about-main-width", layout.width);
		pixel("--about-main-height", layout.height);
		pixel("--about-main-padding", layout.padding);
		pixel("--about-main-padding-top", layout.paddingTop);
		pixel("--about-avatar-size", layout.avatar);
		pixel("--about-name-size", layout.name);
		pixel("--about-main-gap", layout.gap);
		pixel("--about-copy-width", layout.copyWidth);
	};

	const reset = () => {
		root.classList.remove(
			"about-native-scroll",
			"about-motion-page",
			"about-motion-running",
			"about-motion-complete",
		);
		for (const name of properties) page.style.removeProperty(name);
		properties.clear();
		for (const item of items) {
			item.style.removeProperty("opacity");
			item.style.removeProperty("transform");
			item.style.removeProperty("filter");
		}
	};

	const readRaw = () => clamp(-track.getBoundingClientRect().top / distance);
	const render = (raw: number) => {
		// Finish the profile morph before the sticky range ends. The remaining
		// scroll distance gives the short scrub time to settle without a snap.
		const progress = smooth(clamp(raw / 0.68));
		const layout = { ...compact };
		for (const key of Object.keys(layout) as (keyof ProfileLayout)[]) {
			layout[key] = expanded[key] + (compact[key] - expanded[key]) * progress;
		}
		root.classList.toggle("about-motion-running", raw < 1);
		root.classList.toggle("about-motion-complete", raw >= 1);
		mainbox.classList.toggle("is-expanded", narrow || raw < 0.8);
		applyLayout(layout);
		set("--about-main-radius", `${(progress * 0.95).toFixed(3)}rem`);
		set("--about-main-tilt", `${((1 - progress) * -1.35).toFixed(3)}deg`);
		set("--about-main-scale", (1 + (1 - progress) * 0.008).toFixed(4));
		set("--about-main-glow-opacity", (0.28 + (1 - progress) * 0.58).toFixed(3));
		set("--about-main-glow-scale", (0.72 + (1 - progress) * 0.4).toFixed(3));

		// Stagger the first cards as the profile contracts. This avoids forcing a
		// full-page layout read on every animation frame.
		const revealGate = smooth(clamp((raw - 0.28) / 0.58));
		items.forEach((item, index) => {
			const delay = Math.min(index, 5) * 0.07;
			const reveal = clamp((revealGate - delay) / (1 - delay));
			const amount = ease(reveal);
			const remaining = 1 - amount;
			item.style.opacity = amount.toFixed(3);
			item.style.transform = `translate3d(0, ${(24 * remaining).toFixed(2)}px, 0) scale(${(0.975 + amount * 0.025).toFixed(3)})`;
			item.style.filter = "none";
		});
	};

	const requestUpdate = () => {
		if (!active) return;
		const next = readRaw();
		if (Math.abs(next - targetRaw) < 0.0001) return;
		targetRaw = next;
		if (!frame) {
			lastFrameAt = performance.now();
			frame = window.requestAnimationFrame(tick);
		}
	};

	const tick = (now: number) => {
		frame = 0;
		if (!active) return;
		const elapsed = Math.min(80, Math.max(0, now - lastFrameAt));
		lastFrameAt = now;
		const blend = 1 - Math.exp(-elapsed / scrubResponse);
		const change = (targetRaw - displayedRaw) * blend;
		displayedRaw += clamp(change, -maxRawStep, maxRawStep);
		if (Math.abs(displayedRaw - targetRaw) < 0.0005) {
			displayedRaw = targetRaw;
		}
		render(displayedRaw);
		if (displayedRaw !== targetRaw) {
			frame = window.requestAnimationFrame(tick);
			return;
		}
		lastFrameAt = 0;
	};

	const measure = () => {
		if (disposed) return;
		window.cancelAnimationFrame(frame);
		frame = 0;
		narrow = window.innerWidth <= 900;
		active = !media.matches;
		if (!active) {
			reset();
			mainbox.classList.toggle("is-expanded", narrow);
			return;
		}

		root.classList.add("about-native-scroll", "about-motion-page");
		const font = Number.parseFloat(getComputedStyle(root).fontSize) || 16;
		const width = page.clientWidth;
		const height = window.innerHeight;
		const maxWidth =
			(Number.parseFloat(
				getComputedStyle(root).getPropertyValue("--page-width"),
			) || 75) * font;
		const compactWidth = Math.min(maxWidth, width - (narrow ? 24 : 48));
		const padding = (narrow ? 1.15 : 1.65) * font;
		const avatar = narrow ? Math.min(11.4 * font, width * 0.54) : 12 * font;
		const gap = (narrow ? 2.25 : 2) * font;
		compact = {
			top: narrow ? 72 : 82,
			width: compactWidth,
			height: 0,
			padding,
			paddingTop: padding,
			avatar,
			name: narrow
				? Math.min(3.1 * font, width * 0.12)
				: clamp(width * 0.06, 3.4 * font, 4.15 * font),
			gap,
			copyWidth: compactWidth - padding * 2 - (narrow ? 0 : avatar + gap),
		};

		pixel("--about-live-width", compactWidth);
		pixel("--about-live-gap", font);
		root.classList.remove("about-motion-running");
		mainbox.classList.toggle("is-expanded", narrow);
		applyLayout(compact);
		set("--about-main-height", "auto");
		// Measure the actual text and image instead of squeezing a mobile grid into a fixed height.
		compact.height = Math.max((narrow ? 27 : 16) * font, mainbox.offsetHeight);

		const fullPadding = (narrow ? 2.05 : 4.5) * font;
		const fullGap = narrow
			? clamp(height * 0.055, 2.25 * font, 3.25 * font)
			: clamp(width * 0.08, 4 * font, 7 * font);
		const fullAvatar = narrow
			? Math.min(15.5 * font, width * 0.64)
			: Math.min(27 * font, width * 0.3, height - fullPadding * 2);
		const navbarHeight = document.getElementById("top-row")?.offsetHeight || 64;
		expanded = {
			top: 0,
			width,
			height,
			padding: fullPadding,
			paddingTop: narrow
				? Math.max(fullPadding, navbarHeight + font)
				: fullPadding,
			avatar: Math.max(6 * font, fullAvatar),
			name: narrow
				? clamp(width * 0.14, 2.65 * font, 3.8 * font)
				: clamp(width * 0.08, 4.1 * font, 7 * font),
			gap: fullGap,
			copyWidth: narrow
				? width - fullPadding * 2
				: Math.min(35 * font, width - fullPadding * 2 - fullAvatar - fullGap),
		};
		root.classList.add("about-motion-running");
		mainbox.classList.add("is-expanded");
		applyLayout(expanded);
		set("--about-main-height", "auto");
		expanded.height = Math.max(height, mainbox.offsetHeight);

		distance = Math.max(
			height * 2.05,
			narrow ? 720 : 960,
			expanded.height - compact.height - compact.top + 1,
		);
		pixel("--about-scroll-distance", distance);
		pixel(
			"--about-content-height",
			compact.top + compact.height + font + liveStack.offsetHeight + 6 * font,
		);
		pixel(
			"--about-track-height",
			distance +
				compact.top +
				compact.height +
				font +
				liveStack.offsetHeight +
				6 * font,
		);
		targetRaw = readRaw();
		if (!measured) {
			displayedRaw = targetRaw;
			measured = true;
		}
		lastFrameAt = performance.now();
		render(displayedRaw);
		if (Math.abs(displayedRaw - targetRaw) > 0.0001) {
			frame = window.requestAnimationFrame(tick);
		}
	};

	document.addEventListener("scroll", requestUpdate, {
		passive: true,
		capture: true,
	});
	document.addEventListener("focusin", requestUpdate);
	window.addEventListener("scroll", requestUpdate, { passive: true });
	window.addEventListener("resize", measure, { passive: true });
	media.addEventListener("change", measure);
	const observer = new ResizeObserver(measure);
	observer.observe(liveStack);
	measure();
	void document.fonts.ready.then(measure);

	cleanupAboutMotion = () => {
		disposed = true;
		active = false;
		window.cancelAnimationFrame(frame);
		observer.disconnect();
		document.removeEventListener("scroll", requestUpdate, true);
		document.removeEventListener("focusin", requestUpdate);
		window.removeEventListener("scroll", requestUpdate);
		window.removeEventListener("resize", measure);
		media.removeEventListener("change", measure);
		reset();
		mainbox.classList.add("is-expanded");
	};
}
