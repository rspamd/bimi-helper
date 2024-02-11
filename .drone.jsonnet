local IMAGE_NAME = 'rspamd/bimi-helper';

local docker_pipeline = {
  kind: 'pipeline',
  type: 'docker',
};

local docker_defaults = {
  username: {
    from_secret: 'docker_username',
  },
  password: {
    from_secret: 'docker_password',
  },
};

local trigger_on_tag = {
  trigger: {
    branch: {
      include: [
        'main',
      ],
    },
    event: {
      include: [
        'tag',
      ],
    },
  },
};

local platform(arch) = {
  platform: {
    os: 'linux',
    arch: arch,
  },
};

local run_tests(arch) = {
  name: 'test-' + arch,
  steps: [
    {
      name: 'test',
      image: 'rust:1.74',
      environment: {
        RUST_BACKTRACE: 1,
      },
      commands: [
        'rustup component add clippy rustfmt',
        'cargo fmt --all -- --check',
        'cargo clippy -- -D warnings',
        'cargo test',
        'RUST_TEST_THREADS=1 cargo test',
      ],
    },
  ],
  trigger: {
    event: {
      include: [
        'push',
        'pull_request',
      ],
    },
  },
} + docker_pipeline + platform(arch);

local make_docker_image(arch) = {
  name: 'docker-' + arch,
  steps: [
    {
      name: 'docker-build',
      image: 'plugins/docker',
      settings: {
        dockerfile: 'Dockerfile',
        label_schema: [
          'docker.dockerfile=Dockerfile',
        ],
        repo: IMAGE_NAME,
        tags: [
          'latest-' + arch,
        ],
      } + docker_defaults,
    },
  ],
} + platform(arch) + trigger_on_tag + docker_pipeline;

local make_multiarch = {
  local image_tag = 'latest',
  name: 'multiarch_docker_image',
  depends_on: [
    'docker-amd64',
    'docker-arm64',
  ],
  steps: [
    {
      name: 'multiarch_image',
      image: 'plugins/manifest',
      settings: {
        target: std.format('%s:%s', [IMAGE_NAME, image_tag]),
        template: std.format('%s:%s-ARCH', [IMAGE_NAME, image_tag]),
        platforms: [
          'linux/amd64',
          'linux/arm64',
        ],
        tags: [
          '${DRONE_SEMVER_SHORT}',
          '${DRONE_SEMVER_SHORT}-${DRONE_SEMVER_BUILD}',
        ],
      } + docker_defaults,
    },
  ],
} + trigger_on_tag + docker_pipeline;

local signature_placeholder = {
  hmac: '0000000000000000000000000000000000000000000000000000000000000000',
  kind: 'signature',
};

[
  run_tests('amd64'),
  run_tests('arm64'),
  make_docker_image('amd64'),
  make_docker_image('arm64'),
  make_multiarch,
  signature_placeholder,
]
