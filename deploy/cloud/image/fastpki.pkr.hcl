# Packer template — bake a FastPKI AMI on top of Alpine's official cloud image.
#
#   packer init  deploy/cloud/image
#   packer build -only=fastpki.amazon-ebs.alpine -var 'release=1.2.3' deploy/cloud/image
#
# ⚠️ NAME THE SOURCE. The template carries two — the AMI, and a bootable qcow2 emitted from
# the same provision.sh — so a bare `packer build` starts BOTH, and the qemu one needs KVM,
# qemu-system-x86_64 and UEFI firmware on the machine running it. Build the disk through
# deploy/cloud/image/build-qemu.sh, which passes the firmware and captures a guest console.
#
# ── WHY BAKE AN IMAGE RATHER THAN PROVISION AT BOOT ───────────────────────────────────
#
# FastPKI's CA keys live in a PKCS#11 token, and three components in that path are built
# from source with our own patches (see deploy/native/build-native.sh): pkcs11-provider,
# p11-kit and SoftHSM. Alpine's packaged versions are unpatched, and unpatched means an
# Ed25519 or ML-DSA CA cannot be created at all — with an error that names the slot for a
# problem about the algorithm.
#
# Those three have to be built somewhere. Building them at every instance boot would put a
# full toolchain on every production host and add ten minutes to each launch. Building
# them ONCE, here, is the whole argument for a custom image: an instance boots with the
# patched stack and the binaries already in place, and cloud-init only has to answer the
# deployment questions.
#
# ── WHY ON TOP OF ALPINE'S OFFICIAL AMI RATHER THAN AN IMPORTED DISK ─────────────────
#
# Alpine maintains its own cloud-image build system, and the AMIs it publishes already
# support ENA and NVMe EBS. Starting from those means we inherit Alpine's kernel, driver
# and bootloader work on every release instead of re-solving it — and there is no S3
# upload, no vmimport IAM role, and no per-cloud disk format to maintain. The alternative
# (build a raw disk and `aws ec2 import-image` it) buys control over partitioning that we
# do not need and costs exactly the parts that are hardest to get right.

packer {
  required_plugins {
    # The qemu builder produces the bootable disk image. `>=` is a floor, not a pin:
    # `packer init` resolves the newest release at or above it. The floor is what the source
    # block below needs, which is `efi_boot` and the two firmware paths.
    qemu = {
      source  = "github.com/hashicorp/qemu"
      version = ">= 1.1.0"
    }
    amazon = {
      source  = "github.com/hashicorp/amazon"
      version = ">= 1.3.0"
    }
  }
}

variable "region" {
  type        = string
  default     = "us-east-1"
  description = "Region to build the AMI in. Copy it elsewhere with ami_regions."
}

variable "ami_regions" {
  type        = list(string)
  default     = []
  description = "Additional regions to copy the finished AMI into."
}

variable "instance_type" {
  type        = string
  default     = "c7g.2xlarge"
  description = <<-EOT
    Build instance.

    Deliberately large, and the arithmetic is the reason. This compiles FOUR C/C++
    projects — pkcs11-provider, p11-kit, SoftHSM and FastPKI, whose console alone is a
    17.5k-line translation unit — and build-native.sh parallelises to nproc. On a 2-vCPU
    box that is a coin flip against the 60-minute provisioner timeout, and a timeout at
    minute 60 is the worst way to lose a build: everything is thrown away and nothing is
    cached.

    It runs once per release and the instance is terminated at the end, so the cost is
    minutes, not hours. Paying for eight cores to not gamble on that is the cheap side of
    the trade.

    arm64 by default. If you change this to an Intel/AMD type, change source_ami_arch to
    x86_64 to match — and change the deployment's instance_type in deploy/cloud/aws too,
    or the nodes cannot boot the AMI at all.
  EOT
}

variable "source_ami_arch" {
  type        = string
  default     = "aarch64"
  description = "Alpine's architecture token in the AMI name: aarch64 or x86_64."
}

variable "alpine_version" {
  type        = string
  default     = "3.24"
  description = <<-EOT
    Alpine release to build on. This must track the Dockerfile's `FROM alpine:<version>`:
    the container image is the tested surface, and an AMI built on a different release
    would be running the binaries against a different libc and a different OpenSSL from
    the one the suite ran against.
  EOT
}

variable "source_ami_owner" {
  type        = string
  default     = "538276064493"
  description = <<-EOT
    AWS account that publishes Alpine's official cloud images.

    VERIFIED against the EC2 API: this account owns every
    `alpine-3.2*-{aarch64,x86_64}-{uefi,bios}-{cloudinit,tiny}[-metal]-r0` image in
    us-east-1. Re-verify with:

      aws ec2 describe-images --region us-east-1 \
        --filters 'Name=name,Values=alpine-3.24*' 'Name=state,Values=available' \
        --query 'Images[].[OwnerId,Name]' --output text

    ⚠️ AND THE OWNER FILTER IS NOT OPTIONAL. The same query without `--owners` also
    returns images from 679593333241 (aws-marketplace) named
    `alpine-3.20.x-x86_64-solvedevops-build-...` — a third-party seller's build, not
    Alpine's. Nothing about the name tells you which is which, so the owner is the only
    thing standing between "Alpine's official image" and "an image somebody named alpine".
    That is a supply-chain control, not a lookup convenience.

    A variable rather than a hardcoded string so the value can be corrected without
    editing this file if Alpine ever republishes from another account.
  EOT
}

variable "source_ref" {
  type        = string
  default     = "HEAD"
  description = <<-EOT
    The git ref the image is built from. The build refuses a dirty tracked tree, so this
    is how you build something other than your current commit — a tag, for instance, which
    is what a release image should be.
  EOT
}

variable "build_vpc_id" {
  type        = string
  default     = ""
  description = <<-EOT
    VPC to launch the temporary build instance into. Empty uses the account's DEFAULT VPC.

    Many organisations delete the default VPC, and the failure then is
    "VPCIdNotSpecified: No default VPC for this user" twenty seconds into a build — set
    this and build_subnet_id and it goes away. The build instance is temporary and holds
    nothing sensitive: no token is created and no key material exists until an instance is
    configured at first boot.
  EOT
}

variable "build_subnet_id" {
  type        = string
  default     = ""
  description = <<-EOT
    Subnet for the temporary build instance. Required when build_vpc_id is set, and it
    must have outbound internet — the build clones three git repositories, fetches two
    header-only dependencies and installs Alpine packages.
  EOT
}

variable "release" {
  type        = string
  default     = "dev"
  description = "Version tag baked into the AMI name and the fastpki-release file."
}

variable "root_volume_gb" {
  type        = number
  default     = 1
  description = <<-EOT
    Root volume of the build instance, and therefore of every instance launched from the
    resulting AMI — a root volume can never be smaller than the snapshot behind it, so this
    is the ONE place the deployment's root size is decided. deploy/cloud/aws does not pin a
    size of its own; it inherits this.

    1 GB, because that is the size of the PRODUCT: measured, a running node uses 264 MB of
    its root, from a 175 MB image. The build's own needs do not enter into it — the toolchain
    and the object trees go on build_scratch_gb, a volume the builder attaches and throws
    away — which is the whole reason this can be the smallest volume EBS sells rather than
    the ~1 GB high-water mark of a compile.
  EOT
}

variable "build_scratch_gb" {
  type        = number
  default     = 4
  description = <<-EOT
    A scratch volume attached to the BUILD INSTANCE ONLY, where the sources, the object trees
    and the toolchain go. It is not in the AMI and is deleted with the builder, so its size
    costs nothing per deployed node and every gigabyte of the root volume does.

    Measured: the build's high-water mark is about 1 GB (760 MB of build output over ~200 MB
    of base system, sampled every 20 seconds through a bake). 4 GB leaves room for a build
    that grows — a new dependency, a larger translation unit — without anybody having to
    think about it, because unlike the root volume nothing is paying for it afterwards.
  EOT
}

# ── the qemu build: the same image, as a bootable disk ────────────────────────────────
#
# ⚠️ WHY A SECOND BUILDER AT ALL. amazon-ebs produces an AMI, and an AMI can only be
# booted by launching an EC2 instance — so the artifact every cloud user actually boots
# had no local test of any kind. A container is not a substitute and provision.sh says so
# itself: it has no init and no cloud-init, so the two things most likely to be wrong on
# first boot are the two things it cannot check.
#
# This source runs the SAME provision.sh over the SAME Alpine release and emits a qcow2,
# which boots under QEMU on a developer machine and on the lab hypervisor. Same
# provisioning, two outputs: an AMI to ship and a disk image to test.
variable "alpine_image_version" {
  type        = string
  default     = "3.24.1"
  description = <<-EOT
    The PATCH release of alpine_version, which the AMI path never needs: an AMI is chosen
    by filter (`alpine-3.24.*`) and AWS resolves it, while a download URL has no wildcard.
    It must begin with alpine_version, and tests/native_deploy.sh asserts that so the two
    pins cannot drift apart.
  EOT
}

variable "qemu_accelerator" {
  type        = string
  default     = "kvm"
  description = <<-EOT
    kvm on Linux, hvf on macOS, tcg to emulate. tcg works and is slow enough to matter:
    the CI runner has /dev/kvm, so the gate uses kvm and a build takes minutes.
  EOT
}

variable "qemu_efi_code" {
  type        = string
  default     = "/usr/share/OVMF/OVMF_CODE_4M.fd"
  description = <<-EOT
    UEFI firmware for the qemu build. The base is Alpine's `-uefi-` cloud image, so without
    it QEMU falls back to its built-in SeaBIOS, finds no boot code on a GPT disk whose only
    boot path is an EFI system partition, and the build spends its whole ssh_timeout waiting
    for a guest that never started.

    build-qemu.sh overrides this and qemu_efi_vars with whatever the host actually has,
    resolved by deploy/cloud/ovmf-firmware.sh — the same pair boot-check.sh boots the
    finished disk with. The default is the Debian name, so `packer build` run by hand on the
    gate's own Debian runner works without passing anything.

    The amazon-ebs source needs no equivalent: EC2 supplies UEFI firmware to the instance,
    which is why the `-uefi-` choice there costs nothing and the same choice here does.
  EOT
}

variable "qemu_efi_vars" {
  type        = string
  default     = "/usr/share/OVMF/OVMF_VARS_4M.fd"
  description = <<-EOT
    The variable store matching qemu_efi_code — same firmware build, same flash size. Packer
    copies it into the output directory as efivars.fd and boots against the copy, so the file
    named here is never written to.
  EOT
}

variable "build_ssh_public_key" {
  type        = string
  default     = ""
  description = <<-EOT
    An EPHEMERAL public key, generated per build by build-qemu.sh and handed to the VM
    through the cloud-init seed. Packer's own build.SSHPublicKey is not available in a
    source block, and a password would be written into /etc/shadow by cloud-init and
    therefore into the artifact — so the key comes from outside, and the last provisioner
    removes it again along with the cloud-init instance state.
  EOT
}

variable "build_ssh_private_key_file" {
  type        = string
  default     = ""
  description = "The other half of build_ssh_public_key, written by build-qemu.sh into a temporary directory it removes on exit."
}

variable "qemu_output_dir" {
  type        = string
  default     = "output-qemu"
  description = "Directory Packer writes the qcow2 into. Must not already exist."
}

variable "qemu_build_cpus" {
  type        = number
  default     = 2
  description = <<-EOT
    vCPUs for the build VM. build-qemu.sh passes the host's core count, capped, because the
    provisioner compiles pkcs11-provider, p11-kit, SoftHSM and FastPKI against a 60-minute
    timeout — the amazon-ebs source pays for a c7g.2xlarge for exactly this reason.

    The default of 2 is a floor for a host with nothing to spare, and it is genuinely tight:
    two cores got through about 15 of 70 objects an hour on the gate's node.
  EOT
}

variable "qemu_build_memory" {
  type        = number
  default     = 2048
  description = "Megabytes for the build VM. Parallel compilation of a 19k-line translation unit wants headroom per core, so build-qemu.sh raises this with the core count."
}

variable "qemu_console_log" {
  type        = string
  default     = ""
  description = <<-EOT
    Where QEMU writes the build VM's serial console. Empty captures nothing.

    ⚠️ IT MUST NOT SIT INSIDE qemu_output_dir. The qemu builder deletes that directory whole
    when a build halts, so a console log kept there is destroyed by precisely the run worth
    reading. build-qemu.sh passes a sibling path.

    The guest does talk here. Alpine's cloud image puts console=ttyS0,115200n8 on the kernel
    command line, gives GRUB the serial port, and runs a getty on ttyS0 — so the firmware
    banner, the boot menu, the whole kernel log and a login prompt all arrive in this file.
    That is the difference between a guest that never started and a guest that started and
    refused our key, two states packer reports with the same single line.
  EOT
}

locals {
  # No timestamp in the name: Packer's build_time would make every build a new AMI even
  # when nothing changed, and the release tag is the thing an operator actually pins.
  ami_name = "fastpki-${var.release}-alpine${var.alpine_version}-${var.source_ami_arch}"

  # ⚠️ THE `-metal-` TRAP AGAIN, IN URL FORM. The cloud directory publishes
  # generic_alpine-<ver>-x86_64-uefi-cloudinit-r0.qcow2 AND ...-cloudinit-metal-r0.qcow2,
  # exactly the pair the AMI filter above had to disambiguate. A URL cannot glob, so the
  # name is written out in full and names the non-metal build explicitly.
  qemu_base = "generic_alpine-${var.alpine_image_version}-x86_64-uefi-cloudinit-r0.qcow2"
  qemu_url  = "https://dl-cdn.alpinelinux.org/alpine/v${var.alpine_version}/releases/cloud/${local.qemu_base}"
  qemu_name = "fastpki-${var.release}-alpine${var.alpine_version}-x86_64.qcow2"

  # ⚠️ ONE ESCALATION COMMAND FOR BOTH BUILDERS, AND IT IS doas — THE BASE HAS NO sudo.
  # Alpine's cloud images stopped shipping sudo at 3.16: alpine-cloud-images sets
  # `packages.doas = true` in configs/version/base/3.conf and `packages.sudo = null` in
  # base/4.conf, and configs/version/3.24.conf includes base/5.conf → 4 → 3, so 3.24
  # inherits both. sudo is not in Alpine 3.24 main at all. Their scripts/setup writes
  # `permit nopass :wheel` into /etc/doas.d/wheel.conf and puts the `alpine` account in
  # wheel, so this needs nothing seeded from here — which is what makes it right for
  # amazon-ebs, where we supply no user-data and cannot install anything before we have a
  # root shell. configs/cloud/aws.conf adds no packages, so the AMI and the qcow2 carry
  # the same set.
  #
  # `env` is load-bearing: doas resets the environment and, unlike sudo, does NOT accept
  # leading VAR=value assignments — {{ .Vars }} has to be argv of something that sets them.
  # `-n` because a Packer connection has no tty: with the wheel rule in place doas never
  # prompts, and if that rule were ever missing this fails with "doas: Authentication
  # required" rather than blocking on a prompt nothing can answer.
  #
  # provision.sh asks for none of this — it needs uid 0 and nothing else, which is why
  # deploy/native/build-check.sh runs the very same script with a bare `sh` as the
  # container's root. Escalation is a property of arriving over SSH as `alpine`, so it
  # belongs here, once, instead of in the script or in a per-source seed.
  as_root = "chmod +x {{ .Path }}; doas -n env {{ .Vars }} {{ .Path }}"
}

source "amazon-ebs" "alpine" {
  region        = var.region
  ami_name      = local.ami_name
  ami_regions   = var.ami_regions
  instance_type = var.instance_type
  # Alpine's official cloud images ship this account and lock root, so it is the only way
  # in. It escalates with doas, not sudo — see local.as_root. The name comes from the same
  # wiki page as source_ami_owner; verify both together.
  ssh_username = "alpine"

  # Empty means "the default VPC", which is what Packer does with no network set at all.
  vpc_id                      = var.build_vpc_id != "" ? var.build_vpc_id : null
  subnet_id                   = var.build_subnet_id != "" ? var.build_subnet_id : null
  associate_public_ip_address = var.build_subnet_id != "" ? true : null

  # ⚠️ OTHERWISE THE BUILD INSTANCE ANSWERS SSH TO THE INTERNET FOR THE LENGTH OF THE BUILD.
  # Packer's temporary security group defaults to 0.0.0.0/0, and this build is 40 minutes of
  # a host that ends up holding the PKCS#11 stack every CA node will run. Restricting it to
  # the public address of the machine running Packer costs nothing and closes that window.
  # The trade-off is honest: a build driven from a connection whose address changes midway
  # loses its SSH session, which fails the build rather than producing a bad image.
  temporary_security_group_source_public_ip = true

  source_ami_filter {
    filters = {
      # Alpine publishes four dimensions per release: firmware (uefi/bios), flavour
      # (cloudinit/tiny), and a `-metal-` variant of each, all named alike.
      #
      #   cloudinit  the IaC hands the instance its answers file through user-data, so
      #              `tiny` — which has no cloud-init — cannot be configured at all.
      #   uefi       the variant published for both architectures; bios is x86_64-only.
      #
      # ⚠️ THE TRAILING `-r*` IS LORE, NOT STYLE. Without it the pattern also matches
      # `...-uefi-cloudinit-metal-r0`, the bare-metal build, and `most_recent` then has to
      # decide between two different images by creation date. Measured in us-east-1: the
      # aarch64 pair are ONE SECOND apart, and the x86_64 pair carry the IDENTICAL
      # creation timestamp to the second — so nothing breaks the tie and the build takes
      # whichever AWS happens to return first. An image build whose whole purpose is to be
      # pinned and shipped was selecting its own base by coin flip.
      #
      # `-r*` matches only the `-r<N>` revision suffix, which `-metal-r0` never reaches.
      # Verified against the API: exactly one image on both architectures, where the
      # unsuffixed pattern returned two.
      name                = "alpine-${var.alpine_version}.*-${var.source_ami_arch}-uefi-cloudinit-r*"
      root-device-type    = "ebs"
      virtualization-type = "hvm"
    }
    owners      = [var.source_ami_owner]
    most_recent = true
  }

  launch_block_device_mappings {
    device_name           = "/dev/xvda"
    volume_size           = var.root_volume_gb
    volume_type           = "gp3"
    delete_on_termination = true
    encrypted             = true
  }

  # ⚠️ THE BUILD DOES NOT HAPPEN ON THE ROOT VOLUME, SO THE ROOT CAN BE THE SIZE OF THE
  # PRODUCT RATHER THAN THE SIZE OF ITS COMPILER. Measured: the build's high-water mark is
  # about 1 GB — 760 MB of sources, object trees and toolchain over ~200 MB of base system —
  # while the finished node uses 264 MB. Building on the root meant every instance ever
  # launched from this image carried a volume sized for a compiler it does not have.
  #
  # This device is attached to the BUILDER only: it is absent from ami_block_device_mappings,
  # so the AMI does not carry it, and delete_on_termination takes it away with the build
  # instance. provision.sh puts $SRC and the build trees on it and falls back to /tmp when it
  # is not there, which is what the local container bake does.
  launch_block_device_mappings {
    device_name           = "/dev/xvdb"
    volume_size           = var.build_scratch_gb
    volume_type           = "gp3"
    delete_on_termination = true
    encrypted             = true
  }

  # ⚠️ AND THE AMI MUST BE TOLD NOT TO CARRY IT, OR THE WHOLE POINT IS INVERTED. Packer
  # snapshots EVERY volume attached to the builder, so without this the finished image
  # registers two devices — a 1 GB root and a 4 GB snapshot of the scratch disk — and every
  # instance launched from it gets that second volume attached and billed. Measured on the
  # first bake of this change: the AMI came back with two BlockDeviceMappings, which would
  # have made each node cost 5 GB instead of 2, in the name of saving 1.
  #
  # `no_device` on the AMI mapping drops it from the registered image while leaving the
  # builder's own attachment alone.
  ami_block_device_mappings {
    device_name = "/dev/xvdb"
    no_device   = true
  }

  # EBS snapshot encryption for the finished AMI. A FastPKI image carries no keys — the
  # token is created on first boot — but it is cheap and it keeps the launched volumes
  # encrypted by default without every caller having to remember.
  encrypt_boot = true

  tags = {
    Name          = local.ami_name
    Product       = "FastPKI"
    Release       = var.release
    AlpineVersion = var.alpine_version
    BuiltBy       = "packer"
  }
}

source "qemu" "alpine" {
  iso_url = local.qemu_url
  # Alpine publishes a .sha512 beside every cloud image; Packer fetches it and infers the
  # algorithm from the digest length. `none` would mean shipping an artifact built on an
  # unverified base, which is not a trade worth making to save a request.
  iso_checksum = "file:${local.qemu_url}.sha512"
  # The download IS the disk, not an installer to boot — Alpine's cloud image is already
  # a provisioned root filesystem.
  disk_image  = true
  format      = "qcow2"
  disk_size   = "${var.root_volume_gb}G"
  accelerator = var.qemu_accelerator
  headless    = true

  # ⚠️ THE BASE IS THE `-uefi-` CLOUD IMAGE, SO THE FIRMWARE IS PART OF THE BUILD. It is GPT
  # with an EFI system partition and no BIOS boot code, so packer's built-in SeaBIOS has
  # nothing to execute. Alpine install GRUB with --no-nvram and copy it to
  # EFI/boot/bootx64.efi, so a pristine variable store boots it with no NVRAM entry needed.
  #
  # Packer's default machine type, which is `pc`. Alpine build this exact `-uefi-` cloud image
  # on it — their configs/arch/x86_64.conf leaves qemu.machine_type null — so it is the chipset
  # the base is known to boot on. deploy/cloud/boot-check.sh boots the FINISHED disk on q35,
  # and that difference is coverage rather than drift: the artifact has to boot on both.
  efi_boot          = true
  efi_firmware_code = var.qemu_efi_code
  efi_firmware_vars = var.qemu_efi_vars

  # ⚠️ WITHOUT THIS THE GUEST GETS `qemu64`, AND ON A NESTED HOST THAT IS RUINOUS. Packer
  # omits `-cpu` entirely when cpu_model is unset, so QEMU falls back to a baseline model
  # with the host's features masked off. deploy/cloud/boot-check.sh has always passed
  # `-cpu max`; the build half did not, and the two halves of this lane disagreed about the
  # processor the same image runs on.
  #
  # It matters most where this actually runs. The gate's lab-amd64 node is itself a VM, so
  # `accel=kvm` inside it is NESTED virtualisation — and a generic model there is where CPU
  # features stop being passed through from the physical host and start being emulated. The
  # symptom is a build that is accelerated on paper and tens of times slower in practice:
  # this compile reached 15 of 70 objects in 55 minutes, against about six minutes for the
  # same tree on a developer machine.
  #
  # `host` rather than `max`: it passes the underlying processor through as directly as the
  # hypervisor allows, which is the point. The image is never migrated between machines —
  # it is built once and thrown away — so nothing here needs a portable CPU definition.
  cpu_model = "host"

  # ⚠️ SIZED FROM THE HOST, NOT FIXED AT TWO. This compiles four C/C++ projects against a
  # 60-minute provisioner timeout, so cores are the difference between a build that finishes
  # and one that is thrown away at minute 60. build-qemu.sh passes the machine's own core
  # count; the defaults below are the floor for a host that cannot spare more.
  cpus   = var.qemu_build_cpus
  memory = var.qemu_build_memory

  # cloud-init's NoCloud datasource reads a filesystem labelled `cidata`. This is the
  # same mechanism the instance uses in production to receive its answers file, so the
  # build exercises the path it will be configured through.
  cd_label = "cidata"
  cd_content = {
    "meta-data" = "instance-id: fastpki-build\nlocal-hostname: fastpki-build\n"
    "user-data" = <<-EOT
      #cloud-config
      users:
        - name: alpine
          shell: /bin/sh
          # ⚠️ WITHOUT THIS cloud-init RUNS `passwd -l alpine` AND sshd REFUSES OUR KEY. The
          # account already exists in the image with a `*` shadow field, so cloud-init takes
          # its pre-existing-user path: it installs the key and still applies lock_passwd,
          # which defaults to true. OpenSSH with UsePAM unset — Alpine's default — refuses
          # PUBLIC KEY logins for an account whose shadow field begins `!`, not just password
          # ones. The image patches its own cloud.cfg against this, but only for the `default`
          # user entry, and this list does not name `default`.
          lock_passwd: false
          # No sudo or doas key here. The image already carries `permit nopass :wheel` and
          # this account is in wheel, so cloud-init has nothing to add; a `sudo:` key just
          # writes /etc/sudoers.d/90-cloud-init-users for a binary Alpine does not install.
          # cloud-init's `doas:` key would be redundant for the same reason, and
          # write_doas_rules drops the WHOLE ruleset on one malformed entry.
          ssh_authorized_keys:
            - ${var.build_ssh_public_key}
      # ⚠️ THE GUEST'S OWN REPORT, SENT WHERE WE CAN READ IT. qemu_console_log captures ttyS0,
      # and cloud-init's output otherwise goes to /dev/console, which this image points at
      # tty0. These lines put the answers on the serial port instead: whether cloud-init ran,
      # whether the account is usable, whether the key landed, whether sshd is up and whether
      # there is an address. Keep them until this lane has succeeded at least once.
      output: {all: '| tee -a /var/log/cloud-init-output.log /dev/ttyS0'}
      bootcmd:
        - 'echo "FASTPKI-BUILD: bootcmd reached" > /dev/ttyS0'
      runcmd:
        - 'echo "FASTPKI-BUILD: shadow=$(grep "^alpine:" /etc/shadow | cut -d: -f2 | cut -c1) keys=$(cat /home/alpine/.ssh/authorized_keys 2>/dev/null | wc -l) sshd=$(pidof sshd || echo none) esc=$(command -v doas || echo none)" > /dev/ttyS0'
        - 'ip -4 addr show > /dev/ttyS0 2>&1'
    EOT
  }

  ssh_username         = "alpine"
  ssh_private_key_file = var.build_ssh_private_key_file
  # ⚠️ BOTH NUMBERS OR NEITHER. packer-plugin-sdk v0.6.1 communicator/config.go:490-493 fills
  # in ssh_timeout=5m AND ssh_handshake_attempts=10 only when BOTH are unset, so setting one
  # leaves the other at zero. At zero, step_connect_ssh.go:241-242 never returns on an
  # authentication error: a guest whose sshd answers and rejects our key is retried in silence
  # until the timeout, and reports as "Timeout waiting for SSH." — the same line a guest that
  # never booted prints. Ten attempts make that branch abort with an explicit error in about
  # half a minute instead.
  ssh_handshake_attempts = 10
  # ⚠️ THIS BOUNDS THE BOOT, NOT THE BUILD. The compile's budget is the shell provisioner's
  # `timeout = "60m"` further down; nothing here is reached until sshd answers. Ten minutes is
  # far more than an Alpine cloud image needs under KVM, and the slack is deliberate: the
  # authentication branch aborts on its own now, so this only ever bounds a guest that is
  # silent — and a timeout short enough to be its own explanation is worth nothing.
  ssh_timeout      = "10m"
  # doas for the same reason the provisioners use it (local.as_root). This one runs only
  # AFTER the 60-minute compile, so an escalator that does not exist costs a whole
  # successful build. Leaving it empty is not the cheaper option: the builder then stops
  # the VM outright instead of letting the guest sync, and the qcow2 ships an unflushed
  # filesystem.
  shutdown_command = "doas -n poweroff"

  # ⚠️ qemuargs MERGES, IT DOES NOT REPLACE. The builder computes its defaults and then
  # re-inserts every default switch the template did not name (packer-plugin-qemu v1.1.3,
  # builder/qemu/step_run.go:382-393), so naming -serial costs nothing else; -serial is not
  # one of its defaults. Naming -drive or -device here instead WOULD delete both if=pflash
  # firmware units, the cidata seed CD and the root disk in one stroke.
  qemuargs = var.qemu_console_log == "" ? [] : [["-serial", "file:${var.qemu_console_log}"]]

  output_directory = var.qemu_output_dir
  vm_name          = local.qemu_name
}

build {
  name = "fastpki"
  # Both builders run the SAME provisioners over the SAME provision.sh. That is the point:
  # a disk image that was provisioned differently from the AMI would test something other
  # than what ships. Build one with -only=fastpki.amazon-ebs.alpine / .qemu.alpine.
  sources = ["source.amazon-ebs.alpine", "source.qemu.alpine"]

  # ── THE SOURCE IS `git archive`, NOT THE WORKING TREE ───────────────────────────────
  #
  # build-native.sh compiles FastPKI from the tree and applies the three patches out of
  # deploy/, so the builder needs the source. It must NOT get it by uploading the working
  # directory, for the reason deploy/build-image.sh spells out about .dockerignore: the
  # working tree is "files that happen to be here", which is a different population from
  # the tracked set in BOTH directions. It carries a developer's build/ trees, any stray
  # CA material, deploy/.env, the untracked lab plumbing and the gitignored agent guides —
  # and a machine image is a binary redistribution, so anything in it ships.
  #
  # `git archive` is exactly the tracked set: what a fresh clone would carry, nothing else,
  # with no exclusion list to keep in step with reality. third_party/ is gitignored and
  # therefore absent, which is correct — build-native.sh fetches the two header-only deps
  # at their pinned versions itself.
  #
  # ⚠️ THE CONSEQUENCE, STATED PLAINLY: the image is built from a COMMIT, not from your
  # editor. The check below refuses a dirty tracked tree rather than let an uncommitted
  # change be silently absent from a 20-minute build whose whole purpose is to be pinned
  # and shipped.
  provisioner "shell-local" {
    inline = [
      "set -eu",
      "cd '${path.root}/../../..'",
      # ⚠️ THE CLEAN-TREE CHECK APPLIES ONLY TO THE DEFAULT ref, AND THAT IS THE WHOLE
      # POINT OF IT. The danger it guards is a specific one: you believe you are building
      # your current work, and an uncommitted change is silently absent from a 20-minute
      # build. That belief only exists when the ref was not stated.
      #
      # Naming a ref says "build THAT, not my tree", so a dirty working directory is then
      # expected rather than suspicious. Enforcing it anyway would make the build
      # unusable on a tree two people share — one developer's work in progress would
      # block the other's release image, for a reason that has nothing to do with the
      # commit being built.
      "if [ '${var.source_ref}' = HEAD ] && ! git diff --quiet HEAD --; then",
      "  echo 'FATAL: tracked files are modified and no source_ref was given, so the' >&2",
      "  echo '       image would be built from HEAD and your changes would be silently' >&2",
      "  echo '       absent from it. Commit them, or name what to build:' >&2",
      "  echo '           packer build -var source_ref=<commit|tag> ...' >&2",
      "  git --no-pager diff --stat HEAD -- >&2",
      "  exit 1",
      "fi",
      "echo \"==> source: $(git rev-parse --short '${var.source_ref}') ('${var.source_ref}')\"",
      # The same gate deploy/build-image.sh runs before docker: an image must not be built
      # from a tree that fails public-repo hygiene. It runs HERE, on the host, because the
      # claim is about the tracked file set and the repository is right here.
      "bash tests/public_repo_hygiene.sh >/dev/null || { echo 'FATAL: the tree does not pass tests/public_repo_hygiene.sh — not building an image from it.' >&2; exit 1; }",
      "git archive --format=tar.gz -o '${path.root}/.fastpki-src.tar.gz' '${var.source_ref}'",
    ]
  }

  provisioner "file" {
    source      = "${path.root}/.fastpki-src.tar.gz"
    destination = "/tmp/fastpki-src.tar.gz"
    # The shell-local above creates this, so it does not exist when Packer validates the
    # configuration. Without `generated`, `packer validate` stats the path and fails on
    # every clean checkout — which would make the validate gate useless exactly where it
    # is most wanted, in CI.
    generated = true
  }

  provisioner "shell" {
    execute_command  = local.as_root
    environment_vars = ["FASTPKI_RELEASE=${var.release}"]
    script           = "${path.root}/provision.sh"
    # A from-source build of three PKCS#11 components plus FastPKI itself.
    timeout = "60m"
  }

  # The tarball is a build artefact of the host, not of the image. Removed whether the
  # build succeeded or not, so a failed run does not leave a copy of the source tree
  # sitting in the repository.
  provisioner "shell-local" {
    inline = ["rm -f '${path.root}/.fastpki-src.tar.gz'"]
  }

  error-cleanup-provisioner "shell-local" {
    inline = ["rm -f '${path.root}/.fastpki-src.tar.gz'"]
  }

  # ⚠️ THE BUILD KEY MUST NOT SHIP. cloud-init wrote build_ssh_public_key into the alpine
  # account so Packer could connect, and that is a build-time credential — an artifact
  # carrying it would let whoever holds the matching half into every instance booted from
  # it. Clearing the cloud-init instance state matters too: without it the image believes
  # it has already been configured, and a real instance's user-data would be ignored on
  # first boot — which is exactly the failure this whole image exists to let us catch.
  provisioner "shell" {
    only            = ["qemu.alpine"]
    execute_command = local.as_root
    inline = [
      "set -eu",
      "rm -f /home/alpine/.ssh/authorized_keys /root/.ssh/authorized_keys",
      "rm -rf /var/lib/cloud/instance /var/lib/cloud/instances /var/lib/cloud/data",
      "rm -f /etc/machine-id && touch /etc/machine-id",
    ]
  }

  post-processor "manifest" {
    output     = "${path.root}/manifest.json"
    strip_path = true
  }
}
