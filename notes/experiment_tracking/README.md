# Experiment Tracking Overview

This folder outlines a plan to build a persistent telemetry collection and analysis layer for the Advanced Purple Team Lab (APTL).

The goal is to keep experiment data available even when lab resources are destroyed and recreated.

## Objectives

- Provide a stable storage location for logs and metrics from all lab systems
- Support queries across experiments to answer research questions
- Keep the solution simple enough for a single maintainer
- Allow new data sources to be added with minimal effort

## Approach

A dedicated data collector host runs the observability stack. This host uses persistent storage (such as an EBS volume or local disk snapshot) and is not deleted with each lab deployment. Lab machines forward logs and metrics to this host.

Refer to the individual documents in this folder for architecture, telemetry collection details and analysis workflow.
