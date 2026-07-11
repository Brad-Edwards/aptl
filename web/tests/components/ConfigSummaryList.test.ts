import { describe, it, expect, beforeEach } from 'vitest';
import { render, screen } from '@testing-library/svelte';
import ConfigSummaryList from '../../src/lib/components/ConfigSummaryList.svelte';
import { resetPreferences, setPreference } from '../../src/lib/stores/preferences';
import type { AppConfig } from '../../src/lib/types';

function config(overrides: Partial<AppConfig> = {}): AppConfig {
	return {
		lab_name: 'aptl',
		network_subnet: '172.20.0.0/16',
		containers: { wazuh: true, kali: true, reverse: false },
		run_storage_backend: 'local',
		web: {
			build_version: '3.0.10',
			allowed_hosts: ['127.0.0.1', 'localhost'],
			public_origin: null,
			deployment_provider: 'docker-compose'
		},
		...overrides
	};
}

beforeEach(() => {
	localStorage.clear();
	resetPreferences();
});

describe('ConfigSummaryList', () => {
	it('renders lab profile facts', () => {
		render(ConfigSummaryList, { props: { config: config() } });
		expect(screen.getByText('aptl')).toBeTruthy();
		expect(screen.getByText('172.20.0.0/16')).toBeTruthy();
		expect(screen.getByText('local')).toBeTruthy();
	});

	it('lists only the enabled container families', () => {
		render(ConfigSummaryList, { props: { config: config() } });
		expect(screen.getByText('wazuh, kali')).toBeTruthy();
	});

	it('renders web-serve facts and defaults the public origin to loopback', () => {
		render(ConfigSummaryList, { props: { config: config() } });
		expect(screen.getByText('3.0.10')).toBeTruthy();
		expect(screen.getByText('127.0.0.1, localhost')).toBeTruthy();
		expect(screen.getByText('default (loopback)')).toBeTruthy();
		expect(screen.getByText('docker-compose')).toBeTruthy();
	});

	it('shows the public origin when it is set', () => {
		render(ConfigSummaryList, {
			props: {
				config: config({
					web: {
						build_version: '1',
						allowed_hosts: [],
						public_origin: 'https://box.example.ts.net',
						deployment_provider: 'docker-compose'
					}
				})
			}
		});
		expect(screen.getByText('https://box.example.ts.net')).toBeTruthy();
	});

	it('always shows the secrets-hidden note', () => {
		render(ConfigSummaryList, { props: { config: config() } });
		expect(screen.getByText(/intentionally hidden/i)).toBeTruthy();
	});

	it('honours compact density on the row rhythm', () => {
		setPreference('density', 'compact');
		const { container } = render(ConfigSummaryList, { props: { config: config() } });
		expect(container.querySelector('.py-1')).toBeTruthy();
		expect(container.querySelector('.py-2')).toBeNull();
	});
});
