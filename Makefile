SHELL := /bin/bash
export PATH := $(HOME)/.cargo/bin:$(PATH)
export CARGO_TARGET_DIR ?= $(HOME)/.cache/asi-target

# Domyślny DATABASE_URL dla testów integracyjnych (env nadpisuje)
DATABASE_URL ?= postgres://asi:asi_dev_password_change_me@127.0.0.1:5432/asi

COMPOSE_DEV := docker compose -f deploy/docker-compose.dev.yml

.PHONY: fmt clippy test openapi ui-install ui-gen ui-check ui-build dev-up dev-down dd-up dd-init dd-down api worker ui demo-scan ci

fmt:
	cargo fmt --all -- --check

clippy:
	cargo clippy --workspace --all-targets -- -D warnings

test:
	cargo test --workspace

test-db:
	DATABASE_URL=$(DATABASE_URL) cargo test --workspace -- --include-ignored

openapi:
	cargo run -p asi-api -- --export-openapi docs/openapi.json

ui-install:
	cd ui && npm ci

ui-gen: openapi
	cd ui && npm run gen:api

ui-check:
	cd ui && npm run check:i18n && npm run typecheck && npm run lint

ui-build:
	cd ui && npm run build

# --- Środowisko deweloperskie (WSL Ubuntu 22.04 + Docker Desktop) ---
# Baza PostgreSQL + Docker Mock-Lab (cele 172.28.0.0/24, porty na 127.0.0.1:18080..19099)
dev-up:
	$(COMPOSE_DEV) up -d

dev-down:
	$(COMPOSE_DEV) down

# Lokalny DefectDojo (Faza 6) — tylko gdy potrzebny: make dd-up
# UI DefectDojo: http://127.0.0.1:8081 (API v2: /api/v2, auth: Token <api_key>)
dd-up:
	$(COMPOSE_DEV) --profile dd up -d

dd-init:
	$(COMPOSE_DEV) --profile dd exec -T defectdojo ./manage.py migrate --noinput
	DD_SUPERUSER_PASSWORD=$${DD_SUPERUSER_PASSWORD:-ChangeMeNow_Admin123!} \
		$(COMPOSE_DEV) --profile dd exec -T -e DJANGO_SUPERUSER_PASSWORD=$${DD_SUPERUSER_PASSWORD:-ChangeMeNow_Admin123!} \
		defectdojo ./manage.py createsuperuser --noinput --username $${DD_SUPERUSER_USERNAME:-agh} --email agh@agh.local || true
	$(COMPOSE_DEV) --profile dd exec -T defectdojo ./manage.py drf_create_token $${DD_SUPERUSER_USERNAME:-agh} || true
	# świeża baza DD nie ma typów produktów — ASI potrzebuje domyślnego (prod_type przy tworzeniu Product)
	$(COMPOSE_DEV) --profile dd exec -T defectdojo ./manage.py shell -c "from dojo.models import Product_Type; Product_Type.objects.get_or_create(name='AGH Default', defaults={'description': 'ASI default product type'})" 2>/dev/null || true

dd-down:
	$(COMPOSE_DEV) --profile dd down

# Konfiguracja integracji DD w ASI API (token z logu dd-init; bez sekretów w komendzie)
dd-setup:
	bash scripts/dev-dd-setup.sh

# Regeneruje token API dla użytkownika DD i zapisuje do /tmp/dd-token.txt (WSL)
dd-token:
	$(COMPOSE_DEV) --profile dd exec -T defectdojo ./manage.py drf_create_token $${DD_SUPERUSER_USERNAME:-agh} 2>/dev/null | awk '/Generated token/ {print $$3}' > /tmp/dd-token.txt
	@echo "token zapisany do /tmp/dd-token.txt (len=$$(wc -c < /tmp/dd-token.txt))"

# Zrzuca pełny klucz tokena z bazy DD do /tmp/dd-token.txt (WSL)
dd-token-dump:
	$(COMPOSE_DEV) --profile dd exec -T defectdojo ./manage.py shell -c "from rest_framework.authtoken.models import Token; t=Token.objects.first(); open('/tmp/dd-token.txt','w').write(t.key if t else '')" 2>/dev/null
	@echo "dump len=$$(wc -c < /tmp/dd-token.txt)"

# Self-test: token z bazy przeciwko API v2 wewnątrz kontenera + klasy uwierzytelniania
dd-self-test:
	$(COMPOSE_DEV) --profile dd exec -T defectdojo sh -c "K=\$$(cat /tmp/dd-token.txt 2>/dev/null); ./manage.py shell -c \"from rest_framework.authtoken.models import Token; open('/tmp/dd-token.txt','w').write(Token.objects.first().key)\" 2>/dev/null; K=\$$(cat /tmp/dd-token.txt); echo self-test-key-len=\$${#K}; wget -qO- --header=\"Authorization: Token \$$K\" 'http://127.0.0.1:8081/api/v2/users/?limit=1' 2>&1 | head -c 300; echo; ./manage.py shell -c \"from django.conf import settings; print('AUTH:', settings.REST_FRAMEWORK.get('DEFAULT_AUTHENTICATION_CLASSES'))\" 2>/dev/null | tail -1"

# Diagnostyka: użytkownicy i tokeny API w lokalnej bazie DD
dd-inspect:
	$(COMPOSE_DEV) --profile dd exec -T defectdojo ./manage.py shell -c "from django.contrib.auth import get_user_model; from rest_framework.authtoken.models import Token; U=get_user_model(); print('users:', [(u.username, u.is_active, u.is_staff, u.is_superuser) for u in U.objects.all()]); print('tokens:', [(t.key[:8], t.user.username, t.created) for t in Token.objects.all()])" 2>&1 | tail -4

# --- Komponenty (osobne terminale; wszystko na 127.0.0.1 w WSL) ---
api:
	cargo run -p asi-api

worker:
	cargo run -p asi-worker

ui:
	cd ui && npm run dev

# Demo: skan Docker Mock-Lab przez porty publikowane na 127.0.0.1 (działa nawet bez naabu — fallback TCP connect)
demo-scan:
	node scripts/demo-mock-scan.mjs

ci: fmt clippy test ui-gen ui-check ui-build
