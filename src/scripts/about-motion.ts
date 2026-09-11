let cleanupAboutMotion: (() => void) | undefined;

/** Enhance the intro using document scroll, with a normal-flow mobile fallback. */
export function initAboutMotion() {
	cleanupAboutMotion?.();
	cleanupAboutMotion = undefined;

	const page = document.querySelector<HTMLElement>(".about-page");
	const story = page?.querySelector<HTMLElement>(".about-story");
	const stage = page?.querySelector<HTMLElement>(".about-stage");
	const hero = page?.querySelector<HTMLElement>(".about-hero");
	const overview = page?.querySelector<HTMLElement>(".about-overview");
	if (!page || !story || !stage || !hero || !overview) return;

	const media = window.matchMedia(
		"(min-width: 900px) and (min-height: 620px) and (prefers-reduced-motion: no-preference)",
	);
	const panels = [hero, overview];
	let frame = 0;
	let active = false;
	let inset = 0;
	let distance = 1;

	const resetPanels = () => {
		for (const panel of panels) {
			panel.style.removeProperty("opacity");
			panel.style.removeProperty("transform");
			panel.style.removeProperty("visibility");
			panel.inert = false;
			panel.removeAttribute("aria-hidden");
		}
	};

	const clamp = (value: number) => Math.min(1, Math.max(0, value));
	const setPanel = (panel: HTMLElement, opacity: number, y: number) => {
		const hidden = opacity <= 0;
		panel.style.opacity = String(opacity);
		panel.style.transform = `translate3d(0, ${y}px, 0)`;
		panel.style.visibility = hidden ? "hidden" : "visible";
		panel.inert = hidden;
		if (hidden) panel.setAttribute("aria-hidden", "true");
		else panel.removeAttribute("aria-hidden");
	};

	const update = () => {
		frame = 0;
		if (!active) return;
		// Bounding geometry also works with the site's OverlayScrollbars viewport.
		const progress = clamp(
			(inset - story.getBoundingClientRect().top) / distance,
		);
		const exit = clamp((progress - 0.1) / 0.4);
		const enter = clamp((progress - 0.45) / 0.4);
		setPanel(hero, 1 - exit, -36 * exit);
		setPanel(overview, enter, 48 * (1 - enter));
	};

	const requestUpdate = () => {
		if (active && !frame) frame = window.requestAnimationFrame(update);
	};

	const measure = () => {
		window.cancelAnimationFrame(frame);
		frame = 0;
		active = media.matches;
		page.dataset.motion = active ? "scroll" : "static";
		if (!active) {
			resetPanels();
			return;
		}
		inset = Number.parseFloat(getComputedStyle(stage).top) || 0;
		distance = Math.max(1, story.offsetHeight - stage.offsetHeight);
		update();
	};

	// Passive scroll listeners never cancel wheel, touch, or keyboard input.
	document.addEventListener("scroll", requestUpdate, {
		passive: true,
		capture: true,
	});
	window.addEventListener("scroll", requestUpdate, { passive: true });
	window.addEventListener("resize", measure, { passive: true });
	media.addEventListener("change", measure);
	const observer = new ResizeObserver(measure);
	observer.observe(stage);
	measure();

	cleanupAboutMotion = () => {
		active = false;
		window.cancelAnimationFrame(frame);
		observer.disconnect();
		document.removeEventListener("scroll", requestUpdate, true);
		window.removeEventListener("scroll", requestUpdate);
		window.removeEventListener("resize", measure);
		media.removeEventListener("change", measure);
		delete page.dataset.motion;
		resetPanels();
	};
}
