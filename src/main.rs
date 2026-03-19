#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use arboard::Clipboard;
use pillowlock::{
    cleanup_stale_tempfiles, decrypt_file, decrypt_file_with_cancel,
    default_decrypted_output_path_for_kind,
    default_encrypted_output_path, encrypt_file, encrypt_file_with_cancel, generate_keyfile,
    inspect_vault, rewrap_vault, verify_vault, DecryptOptions, EncryptOptions,
    FolderArchiveOptions, FolderCompression, FolderCompressionMethod, PayloadKind, VaultConfig,
    VaultError, VaultSummary, CUSTOM_EXTENSION, LEGACY_CUSTOM_EXTENSION,
};
use rfd::FileDialog;
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};
use slint::winit_030::{winit, EventResult, WinitWindowAccessor};
use slint::{ComponentHandle, ModelRc, SharedString, VecModel};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::rc::Rc;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc, Mutex,
};
use std::{env, thread};

slint::include_modules!();

const APP_TITLE: &str = "PillowLock";
const APP_VERSION: &str = env!("CARGO_PKG_VERSION");
const MAX_RECENT_ITEMS: usize = 10;
const MAX_LOG_ITEMS: usize = 120;
const GITHUB_RELEASES_API_ROOT: &str = "https://api.github.com/repos";
const UPDATE_DOWNLOAD_DIR: &str = "PillowLock-Updates";

fn empty_secret() -> SecretString {
    SecretString::new(String::new().into_boxed_str())
}

fn secret_from_string(value: String) -> SecretString {
    SecretString::new(value.into_boxed_str())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum Mode {
    Encrypt,
    Decrypt,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum Language {
    English,
    Korean,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum SecurityProfile {
    Balanced,
    Hardened,
}

impl SecurityProfile {
    fn config(self) -> VaultConfig {
        match self {
            SecurityProfile::Balanced => VaultConfig {
                chunk_size: 1024 * 1024,
                argon_memory_kib: 262_144,
                argon_iterations: 3,
                argon_lanes: 1,
            },
            SecurityProfile::Hardened => VaultConfig {
                chunk_size: 1024 * 1024,
                argon_memory_kib: 524_288,
                argon_iterations: 4,
                argon_lanes: 1,
            },
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum InputKind {
    File,
    Folder,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum CompressionPreset {
    Fast,
    Balanced,
    Maximum,
    None,
}

impl CompressionPreset {
    fn folder_compression(self) -> FolderCompression {
        match self {
            CompressionPreset::Fast => FolderCompression {
                method: FolderCompressionMethod::Deflated,
                level: Some(1),
            },
            CompressionPreset::Balanced => FolderCompression {
                method: FolderCompressionMethod::Deflated,
                level: Some(6),
            },
            CompressionPreset::Maximum => FolderCompression {
                method: FolderCompressionMethod::Deflated,
                level: Some(9),
            },
            CompressionPreset::None => FolderCompression {
                method: FolderCompressionMethod::Stored,
                level: None,
            },
        }
    }
}

#[derive(Debug, Clone)]
struct UpdateUiState {
    repo_slug: Option<String>,
    checking: bool,
    checked_once: bool,
    available: bool,
    current_version: String,
    latest_version: Option<String>,
    status_line: String,
    details: String,
    release_url: Option<String>,
    download_url: Option<String>,
    download_asset_name: Option<String>,
}

impl UpdateUiState {
    fn new(language: Language) -> Self {
        let repo_slug = configured_update_repo();
        let mut state = Self {
            repo_slug,
            checking: false,
            checked_once: false,
            available: false,
            current_version: APP_VERSION.to_owned(),
            latest_version: None,
            status_line: String::new(),
            details: String::new(),
            release_url: None,
            download_url: None,
            download_asset_name: None,
        };
        state.apply_default_copy(language);
        state
    }

    fn apply_default_copy(&mut self, language: Language) {
        if self.checked_once || self.checking {
            return;
        }
        match (&self.repo_slug, language) {
            (Some(repo), Language::English) => {
                self.status_line = "Ready to check GitHub releases.".to_owned();
                self.details = format!(
                    "Current version: {APP_VERSION}\nGitHub repository: {repo}\nRelease builds can check and install updates from GitHub Releases."
                );
            }
            (Some(repo), Language::Korean) => {
                self.status_line = "GitHub 릴리스를 확인할 준비가 되었습니다.".to_owned();
                self.details = format!(
                    "현재 버전: {APP_VERSION}\nGitHub 저장소: {repo}\n릴리스 빌드에서는 GitHub Releases에서 업데이트를 확인하고 설치할 수 있습니다."
                );
            }
            (None, Language::English) => {
                self.status_line = "Updater is disabled for this local build.".to_owned();
                self.details =
                    "Set PILLOWLOCK_UPDATE_REPO at build time to enable in-app GitHub update checks.".to_owned();
            }
            (None, Language::Korean) => {
                self.status_line = "이 로컬 빌드에서는 업데이트 확인이 비활성화되어 있습니다.".to_owned();
                self.details = "앱 내 GitHub 업데이트 확인을 쓰려면 빌드 시 PILLOWLOCK_UPDATE_REPO를 설정하세요.".to_owned();
            }
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum StatusTone {
    Idle,
    Working,
    Success,
    Error,
}

impl StatusTone {
    fn code(self) -> i32 {
        match self {
            StatusTone::Idle => 0,
            StatusTone::Working => 1,
            StatusTone::Success => 2,
            StatusTone::Error => 3,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum QueueStatus {
    Pending,
    Running,
    Success,
    Failed,
    Cancelled,
}

impl QueueStatus {
    fn is_finished(self) -> bool {
        matches!(self, QueueStatus::Success | QueueStatus::Failed | QueueStatus::Cancelled)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct RecentSuccess {
    mode: Mode,
    input_path: String,
    output_path: String,
    profile: SecurityProfile,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(default)]
struct PersistedSettings {
    language: Option<Language>,
    mode: Option<Mode>,
    profile: Option<SecurityProfile>,
    input_kind: Option<InputKind>,
    compression_preset: Option<CompressionPreset>,
    compression_advanced: bool,
    compression_method: Option<FolderCompressionMethod>,
    compression_level: Option<i32>,
    last_output_folder: Option<String>,
    last_success_mode: Option<Mode>,
    last_success_profile: Option<SecurityProfile>,
    recent_inputs: Vec<String>,
    recent_output_folders: Vec<String>,
    recent_successes: Vec<RecentSuccess>,
    show_queue: bool,
    queue_recursive: bool,
}

#[derive(Debug, Clone)]
struct QueuedJob {
    id: u64,
    mode: Mode,
    input_kind: InputKind,
    payload_kind: PayloadKind,
    input_path: String,
    output_path: String,
    keyfile_path_session: Option<String>,
    folder_compression: Option<FolderCompression>,
    profile: SecurityProfile,
    status: QueueStatus,
    progress: i32,
    last_error: Option<String>,
}

#[derive(Debug)]
struct AppState {
    language: Language,
    mode: Mode,
    profile: SecurityProfile,
    input_kind: InputKind,
    selected_payload_kind: PayloadKind,
    compression_preset: CompressionPreset,
    compression_advanced: bool,
    compression_method: FolderCompressionMethod,
    compression_level: i32,
    show_advanced: bool,
    show_settings: bool,
    show_queue: bool,
    queue_recursive: bool,
    input_path: String,
    output_path: String,
    keyfile_path: String,
    password: SecretString,
    confirm_password: SecretString,
    rotate_password: SecretString,
    rotate_confirm_password: SecretString,
    rotate_keyfile_path: String,
    status_line: String,
    status_tone: StatusTone,
    logs: Vec<String>,
    running: bool,
    drop_hovered: bool,
    recent_inputs: Vec<String>,
    recent_output_folders: Vec<String>,
    recent_successes: Vec<RecentSuccess>,
    last_output_folder: Option<String>,
    last_completed_input: Option<String>,
    last_completed_output: Option<String>,
    last_success_mode: Option<Mode>,
    last_success_profile: Option<SecurityProfile>,
    queue_items: Vec<QueuedJob>,
    selected_queue_job: Option<u64>,
    next_queue_job_id: u64,
    queue_running: bool,
    queue_stop_requested: bool,
    current_queue_job: Option<u64>,
    queue_cancel_flag: Arc<AtomicBool>,
    advanced_tool_output: String,
    update_ui: UpdateUiState,
    session_keyfile_cache: Vec<String>,
}

#[derive(Debug)]
struct JobRequest {
    input: PathBuf,
    output: PathBuf,
    keyfile: Option<PathBuf>,
    input_kind: InputKind,
    folder_compression: Option<FolderCompression>,
    language: Language,
    mode: Mode,
    profile: SecurityProfile,
    password: SecretString,
}

#[derive(Debug)]
struct VerifyRequest {
    input: PathBuf,
    keyfile: Option<PathBuf>,
    language: Language,
    password: SecretString,
}

#[derive(Debug)]
struct RotateRequest {
    input: PathBuf,
    output: PathBuf,
    old_keyfile: Option<PathBuf>,
    new_keyfile: Option<PathBuf>,
    language: Language,
    old_password: SecretString,
    new_password: SecretString,
}

#[derive(Debug, Clone)]
struct QueueRunRequest {
    items: Vec<QueuedJob>,
    language: Language,
    password: SecretString,
    cancel_flag: Arc<AtomicBool>,
}

#[derive(Debug)]
struct UpdateCheckRequest {
    repo_slug: String,
}

#[derive(Debug)]
struct UpdateInstallRequest {
    download_url: String,
    asset_name: String,
}

#[derive(Debug, Clone, Deserialize)]
struct GitHubReleaseAsset {
    name: String,
    browser_download_url: String,
}

#[derive(Debug, Clone, Deserialize)]
struct GitHubReleaseResponse {
    tag_name: String,
    html_url: String,
    body: Option<String>,
    assets: Vec<GitHubReleaseAsset>,
}

#[derive(Debug, Clone)]
struct UpdateReleaseInfo {
    repo_slug: String,
    tag_name: String,
    version: String,
    release_url: String,
    download_url: Option<String>,
    asset_name: Option<String>,
    release_notes_excerpt: Option<String>,
    available: bool,
}

impl Default for AppState {
    fn default() -> Self {
        Self {
            language: Language::English,
            mode: Mode::Encrypt,
            profile: SecurityProfile::Balanced,
            input_kind: InputKind::File,
            selected_payload_kind: PayloadKind::SingleFile,
            compression_preset: CompressionPreset::Balanced,
            compression_advanced: false,
            compression_method: FolderCompressionMethod::Deflated,
            compression_level: 6,
            show_advanced: false,
            show_settings: false,
            show_queue: false,
            queue_recursive: false,
            input_path: String::new(),
            output_path: String::new(),
            keyfile_path: String::new(),
            password: empty_secret(),
            confirm_password: empty_secret(),
            rotate_password: empty_secret(),
            rotate_confirm_password: empty_secret(),
            rotate_keyfile_path: String::new(),
            status_line: "Choose a file or folder to get started.".to_owned(),
            status_tone: StatusTone::Idle,
            logs: vec!["PillowLock ready.".to_owned()],
            running: false,
            drop_hovered: false,
            recent_inputs: Vec::new(),
            recent_output_folders: Vec::new(),
            recent_successes: Vec::new(),
            last_output_folder: None,
            last_completed_input: None,
            last_completed_output: None,
            last_success_mode: None,
            last_success_profile: None,
            queue_items: Vec::new(),
            selected_queue_job: None,
            next_queue_job_id: 1,
            queue_running: false,
            queue_stop_requested: false,
            current_queue_job: None,
            queue_cancel_flag: Arc::new(AtomicBool::new(false)),
            advanced_tool_output: "Use Inspect, Verify, or Rotate Keys for the selected protected file.".to_owned(),
            update_ui: UpdateUiState::new(Language::English),
            session_keyfile_cache: Vec::new(),
        }
    }
}

impl AppState {
    fn from_settings(settings: PersistedSettings) -> Self {
        let mut state = Self::default();
        if let Some(language) = settings.language {
            state.language = language;
        }
        if let Some(mode) = settings.mode {
            state.mode = mode;
        }
        if let Some(profile) = settings.profile {
            state.profile = profile;
        }
        if let Some(input_kind) = settings.input_kind {
            state.input_kind = input_kind;
        }
        if let Some(compression_preset) = settings.compression_preset {
            state.compression_preset = compression_preset;
        }
        state.compression_advanced = settings.compression_advanced;
        if let Some(compression_method) = settings.compression_method {
            state.compression_method = compression_method;
        }
        if let Some(compression_level) = settings.compression_level {
            state.compression_level = compression_level.clamp(0, 9);
        }
        state.last_output_folder = settings.last_output_folder;
        state.last_success_mode = settings.last_success_mode;
        state.last_success_profile = settings.last_success_profile;
        state.recent_inputs = settings.recent_inputs;
        state.recent_output_folders = settings.recent_output_folders;
        state.recent_successes = settings.recent_successes;
        state.show_queue = settings.show_queue;
        state.queue_recursive = settings.queue_recursive;
        state.selected_payload_kind = if state.input_kind == InputKind::Folder {
            PayloadKind::FolderArchive
        } else {
            PayloadKind::SingleFile
        };
        state.prune_recent_entries();
        state.update_ui = UpdateUiState::new(state.language);
        state
    }

    fn to_settings(&self) -> PersistedSettings {
        PersistedSettings {
            language: Some(self.language),
            mode: Some(self.mode),
            profile: Some(self.profile),
            input_kind: Some(self.input_kind),
            compression_preset: Some(self.compression_preset),
            compression_advanced: self.compression_advanced,
            compression_method: Some(self.compression_method),
            compression_level: Some(self.compression_level.clamp(0, 9)),
            last_output_folder: self.last_output_folder.clone(),
            last_success_mode: self.last_success_mode,
            last_success_profile: self.last_success_profile,
            recent_inputs: self.recent_inputs.clone(),
            recent_output_folders: self.recent_output_folders.clone(),
            recent_successes: self.recent_successes.clone(),
            show_queue: self.show_queue,
            queue_recursive: self.queue_recursive,
        }
    }

    fn save_settings(&self) -> std::io::Result<()> {
        let Some(path) = settings_path() else {
            return Ok(());
        };
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        let bytes = serde_json::to_vec_pretty(&self.to_settings())?;
        fs::write(path, bytes)
    }

    fn tr<'a>(&self, en: &'a str, ko: &'a str) -> &'a str {
        match self.language {
            Language::English => en,
            Language::Korean => ko,
        }
    }

    fn busy(&self) -> bool {
        self.running || self.queue_running
    }

    fn current_input_payload_kind(&self) -> PayloadKind {
        match self.mode {
            Mode::Encrypt => {
                if self.input_kind == InputKind::Folder {
                    PayloadKind::FolderArchive
                } else {
                    PayloadKind::SingleFile
                }
            }
            Mode::Decrypt => self.selected_payload_kind,
        }
    }

    fn effective_folder_compression(&self) -> FolderCompression {
        if self.compression_advanced {
            match self.compression_method {
                FolderCompressionMethod::Stored => FolderCompression {
                    method: FolderCompressionMethod::Stored,
                    level: None,
                },
                FolderCompressionMethod::Deflated => FolderCompression {
                    method: FolderCompressionMethod::Deflated,
                    level: Some(self.compression_level.clamp(0, 9)),
                },
            }
        } else {
            self.compression_preset.folder_compression()
        }
    }

    fn output_target_is_directory(&self) -> bool {
        self.mode == Mode::Decrypt && self.selected_payload_kind == PayloadKind::FolderArchive
    }

    fn default_status(&self) -> &'static str {
        if self.mode == Mode::Encrypt && self.input_kind == InputKind::Folder {
            self.tr("Choose a folder to get started.", "폴더를 선택해 시작하세요.")
        } else if self.mode == Mode::Encrypt {
            self.tr("Choose a file or folder to get started.", "파일이나 폴더를 선택해 시작하세요.")
        } else {
            self.tr("Choose a protected file to get started.", "보호 파일을 선택해 시작하세요.")
        }
    }

    fn password_text(&self) -> &str {
        self.password.expose_secret()
    }

    fn confirm_password_text(&self) -> &str {
        self.confirm_password.expose_secret()
    }

    fn rotate_password_text(&self) -> &str {
        self.rotate_password.expose_secret()
    }

    fn rotate_confirm_password_text(&self) -> &str {
        self.rotate_confirm_password.expose_secret()
    }

    fn has_input_file(&self) -> bool {
        !self.input_path.trim().is_empty()
    }

    fn has_output_path(&self) -> bool {
        !self.output_path.trim().is_empty()
    }

    fn can_start(&self) -> bool {
        !self.busy()
            && self.has_input_file()
            && self.has_output_path()
            && !self.password_text().is_empty()
            && (self.mode == Mode::Decrypt || self.password_text() == self.confirm_password_text())
    }

    fn can_queue_add(&self) -> bool {
        !self.busy() && self.has_input_file() && self.has_output_path()
    }

    fn can_queue_run(&self) -> bool {
        !self.busy()
            && self
                .queue_items
                .iter()
                .any(|item| matches!(item.status, QueueStatus::Pending))
    }

    fn can_queue_retry(&self) -> bool {
        !self.busy()
            && self
                .queue_items
                .iter()
                .any(|item| matches!(item.status, QueueStatus::Failed))
    }

    fn can_queue_remove(&self) -> bool {
        !self.busy()
            && self.selected_queue_job.is_some()
            && self
                .selected_queue_job
                .and_then(|id| self.queue_items.iter().find(|item| item.id == id))
                .map(|item| item.status != QueueStatus::Running)
                .unwrap_or(false)
    }

    fn can_inspect(&self) -> bool {
        !self.busy() && self.has_input_file()
    }

    fn can_verify(&self) -> bool {
        !self.busy() && self.has_input_file() && !self.password_text().is_empty()
    }

    fn can_rotate(&self) -> bool {
        !self.busy()
            && self.has_input_file()
            && self.has_output_path()
            && !self.password_text().is_empty()
            && !self.rotate_password_text().is_empty()
            && self.rotate_password_text() == self.rotate_confirm_password_text()
    }

    fn can_check_updates(&self) -> bool {
        self.update_ui.repo_slug.is_some() && !self.update_ui.checking
    }

    fn can_install_update(&self) -> bool {
        !self.busy()
            && !self.update_ui.checking
            && self.update_ui.available
            && self.update_ui.download_url.is_some()
    }

    fn can_open_release_page(&self) -> bool {
        self.update_ui.release_url.is_some() && !self.update_ui.checking
    }

    fn readiness_hint(&self) -> &'static str {
        if self.running {
            return self.tr("A task is currently running.", "작업이 진행 중입니다.");
        }
        if self.queue_running {
            return self.tr("The queue is currently running.", "배치 큐가 진행 중입니다.");
        }
        if !self.has_input_file() {
            return match (self.mode, self.input_kind) {
                (Mode::Encrypt, InputKind::Folder) => {
                    self.tr("Choose an input folder.", "입력 폴더를 선택하세요.")
                }
                (Mode::Encrypt, InputKind::File) => {
                    self.tr("Choose an input file or folder.", "입력 파일이나 폴더를 선택하세요.")
                }
                (Mode::Decrypt, _) => self.tr("Choose a protected file.", "보호 파일을 선택하세요."),
            };
        }
        if !self.has_output_path() {
            if self.output_target_is_directory() {
                return self.tr(
                    "Choose where the restored folder should be created.",
                    "복원된 폴더를 만들 위치를 선택하세요.",
                );
            }
            return self.tr("Choose where the result should be saved.", "결과 파일 위치를 정하세요.");
        }
        if self.password_text().is_empty() {
            return self.tr("Enter a password.", "비밀번호를 입력하세요.");
        }
        if self.mode == Mode::Encrypt && self.password_text() != self.confirm_password_text() {
            return self.tr("Password confirmation must match.", "비밀번호 확인이 일치해야 합니다.");
        }
        self.tr("Ready to run.", "실행할 준비가 되었습니다.")
    }

    fn mode_label(&self, mode: Mode) -> &'static str {
        match mode {
            Mode::Encrypt => self.tr("Encrypt", "암호화"),
            Mode::Decrypt => self.tr("Decrypt", "복호화"),
        }
    }

    fn profile_label(&self, profile: SecurityProfile) -> &'static str {
        match profile {
            SecurityProfile::Balanced => self.tr("Balanced", "균형"),
            SecurityProfile::Hardened => self.tr("Hardened", "강화"),
        }
    }

    fn input_kind_label(&self, input_kind: InputKind) -> &'static str {
        match input_kind {
            InputKind::File => self.tr("File", "파일"),
            InputKind::Folder => self.tr("Folder", "폴더"),
        }
    }

    fn compression_preset_label(&self, preset: CompressionPreset) -> &'static str {
        match preset {
            CompressionPreset::Fast => self.tr("Fast", "빠름"),
            CompressionPreset::Balanced => self.tr("Balanced", "균형"),
            CompressionPreset::Maximum => self.tr("Maximum", "최대"),
            CompressionPreset::None => self.tr("No compression", "무압축"),
        }
    }

    fn payload_kind_label(&self, payload_kind: PayloadKind) -> &'static str {
        match payload_kind {
            PayloadKind::SingleFile => self.tr("Single file", "단일 파일"),
            PayloadKind::FolderArchive => self.tr("Folder archive", "폴더 아카이브"),
        }
    }

    fn mode_group_hint(&self) -> &'static str {
        match self.mode {
            Mode::Encrypt => self.tr(
                "Encrypt is selected. PillowLock will create a new .plock copy and keep your original file untouched.",
                "암호화가 선택되었습니다. PillowLock가 새 .plock 사본을 만들고 원본 파일은 그대로 둡니다.",
            ),
            Mode::Decrypt => self.tr(
                "Decrypt is selected. PillowLock will open an existing .plock protected file and restore the file to a new path.",
                "복호화가 선택되었습니다. 기존 .plock 보호 파일을 열고 파일을 새 경로로 복원합니다.",
            ),
        }
    }

    fn profile_group_hint(&self) -> &'static str {
        match self.profile {
            SecurityProfile::Balanced => self.tr(
                "Balanced is selected. It fits everyday use and unlocks faster on most PCs.",
                "균형이 선택되었습니다. 일상적인 사용에 잘 맞고 대부분의 PC에서 더 빠르게 처리됩니다.",
            ),
            SecurityProfile::Hardened => self.tr(
                "Hardened is selected. It spends more memory to resist password guessing more strongly.",
                "강화가 선택되었습니다. 비밀번호 추측 공격을 더 강하게 막기 위해 메모리를 더 사용합니다.",
            ),
        }
    }

    fn queue_status_label(&self, status: QueueStatus) -> &'static str {
        match status {
            QueueStatus::Pending => self.tr("Pending", "대기"),
            QueueStatus::Running => self.tr("Running", "진행 중"),
            QueueStatus::Success => self.tr("Done", "완료"),
            QueueStatus::Failed => self.tr("Failed", "실패"),
            QueueStatus::Cancelled => self.tr("Cancelled", "취소"),
        }
    }

    fn action_label(&self) -> &'static str {
        match self.mode {
            Mode::Encrypt if self.input_kind == InputKind::Folder => {
                self.tr("Create Protected Archive", "보호 아카이브 만들기")
            }
            Mode::Encrypt => self.tr("Create Protected File", "보호 파일 만들기"),
            Mode::Decrypt => self.tr("Restore Original File", "원본 파일 복원"),
        }
    }

    fn action_caption(&self) -> &'static str {
        match self.mode {
            Mode::Encrypt if self.input_kind == InputKind::Folder => self.tr(
                "PillowLock packages the folder into a temporary ZIP, then encrypts it into one protected file.",
                "PillowLock이 폴더를 임시 ZIP으로 묶은 뒤 하나의 보호 파일로 암호화합니다.",
            ),
            Mode::Encrypt => self.tr(
                "PillowLock creates a new .plock file and leaves the original file untouched.",
                "PillowLock는 새 .plock 파일을 만들고 원본 파일은 그대로 둡니다.",
            ),
            Mode::Decrypt => self.tr(
                "The restored file is written to a new location instead of changing the protected file.",
                "복원된 파일은 보호 파일을 바꾸지 않고 새 위치에 저장됩니다.",
            ),
        }
    }

    fn workspace_title(&self) -> &'static str {
        match self.mode {
            Mode::Encrypt if self.input_kind == InputKind::Folder => {
                self.tr("Protect a folder", "폴더 보호")
            }
            Mode::Encrypt => self.tr("Protect a file", "파일 보호"),
            Mode::Decrypt => self.tr("Restore a protected file", "보호 파일 복원"),
        }
    }

    fn workspace_subtitle(&self) -> &'static str {
        match self.mode {
            Mode::Encrypt if self.input_kind == InputKind::Folder => self.tr(
                "Pick a folder, choose compression, add a password, and build a single protected archive.",
                "폴더를 고르고 압축을 선택한 뒤 비밀번호를 추가해 하나의 보호 아카이브를 만드세요.",
            ),
            Mode::Encrypt => self.tr(
                "Pick a file, add a password, and build a layered protected file.",
                "파일을 고르고 비밀번호를 더해 계층형 보호 파일을 만드세요.",
            ),
            Mode::Decrypt => self.tr(
                "Open an existing .plock file and recover the original content to a new path.",
                "기존 .plock 파일을 열고 원본 내용을 새 경로로 복원하세요.",
            ),
        }
    }

    fn source_surface_title(&self) -> &'static str {
        if self.drop_hovered {
            match self.mode {
                Mode::Encrypt => self.tr("Release to add this item", "놓으면 이 항목을 추가합니다"),
                Mode::Decrypt => self.tr("Release to add this file", "놓으면 이 파일을 추가합니다"),
            }
        } else if !self.has_input_file() {
            match self.mode {
                Mode::Encrypt => self.tr("Drop a file or folder here", "여기로 파일이나 폴더를 끌어오세요"),
                Mode::Decrypt => self.tr("Drop a protected file here", "여기로 보호 파일을 끌어오세요"),
            }
        } else {
            match self.mode {
                Mode::Encrypt if self.input_kind == InputKind::Folder => {
                    self.tr("Ready to protect this folder", "이 폴더를 보호할 준비가 됐습니다")
                }
                Mode::Encrypt => self.tr("Ready to protect this file", "이 파일을 보호할 준비가 됐습니다"),
                Mode::Decrypt if self.selected_payload_kind == PayloadKind::FolderArchive => {
                    self.tr("Ready to restore this protected folder", "이 보호 폴더를 복원할 준비가 됐습니다")
                }
                Mode::Decrypt => self.tr("Ready to restore this protected file", "이 보호 파일을 복원할 준비가 됐습니다"),
            }
        }
    }

    fn source_surface_subtitle(&self) -> &'static str {
        if self.drop_hovered {
            self.tr("Drop now and PillowLock will wire the next steps for you.", "지금 놓으면 PillowLock이 다음 단계를 바로 채웁니다.")
        } else if !self.has_input_file() {
            match self.mode {
                Mode::Encrypt => self.tr(
                    "Drag a file or folder here or browse. Multiple drops are added to the queue.",
                    "파일이나 폴더를 끌어오거나 찾아보세요. 여러 항목은 큐에 추가됩니다.",
                ),
                Mode::Decrypt => self.tr(
                    "Drag a protected file here or browse. Multiple drops are added to the queue.",
                    "보호 파일을 끌어오거나 찾아보세요. 여러 파일은 큐에 추가됩니다.",
                ),
            }
        } else if self.mode == Mode::Encrypt && self.input_kind == InputKind::Folder {
            self.tr(
                "You can switch folders, tune compression, or add more work to the queue at any time.",
                "언제든 다른 폴더로 바꾸고 압축을 조정하거나 큐에 더 추가할 수 있습니다.",
            )
        } else {
            self.tr("You can switch files or add more work to the queue at any time.", "언제든 다른 파일로 바꾸거나 큐에 더 추가할 수 있습니다.")
        }
    }

    fn password_subtitle(&self) -> &'static str {
        match self.mode {
            Mode::Encrypt => self.tr(
                "Use a strong password. The confirmation field catches typos before sealing the protected file.",
                "강한 비밀번호를 사용하세요. 확인 입력란으로 보호 파일을 만들기 전 오타를 미리 막을 수 있습니다.",
            ),
            Mode::Decrypt => self.tr(
                "Enter the password that was used when this protected file was created.",
                "이 보호 파일을 만들 때 사용한 비밀번호를 입력하세요.",
            ),
        }
    }

    fn add_log(&mut self, message: impl Into<String>) {
        self.logs.push(message.into());
        if self.logs.len() > MAX_LOG_ITEMS {
            let excess = self.logs.len() - MAX_LOG_ITEMS;
            self.logs.drain(0..excess);
        }
    }

    fn set_status(&mut self, tone: StatusTone, message: impl Into<String>) {
        self.status_tone = tone;
        self.status_line = message.into();
    }

    fn trimmed_path(value: &str) -> Option<PathBuf> {
        let trimmed = value.trim();
        if trimmed.is_empty() {
            None
        } else {
            Some(PathBuf::from(trimmed))
        }
    }

    fn remember_session_keyfile(&mut self, value: &str) {
        let trimmed = value.trim();
        if trimmed.is_empty() {
            return;
        }
        if !self.session_keyfile_cache.iter().any(|item| item == trimmed) {
            self.session_keyfile_cache.push(trimmed.to_owned());
        }
    }

    fn preferred_output_for(&self, input: &Path, mode: Mode, payload_kind: PayloadKind) -> PathBuf {
        let suggested = match mode {
            Mode::Encrypt => default_encrypted_output_path(input),
            Mode::Decrypt => default_decrypted_output_path_for_kind(input, payload_kind),
        };
        if let Some(folder) = self.last_output_folder.as_ref().map(PathBuf::from) {
            if folder.is_dir() {
                if let Some(file_name) = suggested.file_name() {
                    return folder.join(file_name);
                }
            }
        }
        suggested
    }

    fn refresh_output_suggestion(&mut self) {
        if let Some(input) = Self::trimmed_path(&self.input_path) {
            self.output_path = self
                .preferred_output_for(&input, self.mode, self.current_input_payload_kind())
                .display()
                .to_string();
        }
    }

    fn clear_passwords(&mut self) {
        self.password = empty_secret();
        self.confirm_password = empty_secret();
    }

    fn clear_rotate_passwords(&mut self) {
        self.rotate_password = empty_secret();
        self.rotate_confirm_password = empty_secret();
    }

    fn clear_form(&mut self) {
        self.input_path.clear();
        self.output_path.clear();
        self.keyfile_path.clear();
        self.clear_passwords();
        self.clear_rotate_passwords();
        self.rotate_keyfile_path.clear();
        let message = self.tr("Fields have been reset.", "입력값을 초기화했습니다.").to_owned();
        self.set_status(StatusTone::Idle, message.clone());
        self.add_log(message);
    }

    fn set_mode(&mut self, mode: Mode) {
        if self.mode != mode {
            self.mode = mode;
            if self.mode == Mode::Encrypt {
                self.selected_payload_kind = if self.input_kind == InputKind::Folder {
                    PayloadKind::FolderArchive
                } else {
                    PayloadKind::SingleFile
                };
            } else if let Some(input) = Self::trimmed_path(&self.input_path) {
                self.selected_payload_kind = inspect_vault(&input)
                    .map(|summary| summary.payload_kind)
                    .unwrap_or(PayloadKind::SingleFile);
            }
            if self.has_input_file() {
                self.refresh_output_suggestion();
            }
            if !self.busy() {
                self.set_status(StatusTone::Idle, self.default_status());
            }
        }
    }

    fn set_input_kind(&mut self, input_kind: InputKind) {
        if self.input_kind == input_kind {
            return;
        }
        self.input_kind = input_kind;
        self.selected_payload_kind = if input_kind == InputKind::Folder {
            PayloadKind::FolderArchive
        } else {
            PayloadKind::SingleFile
        };

        if let Some(input) = Self::trimmed_path(&self.input_path) {
            let mismatched = (input_kind == InputKind::Folder && input.is_file())
                || (input_kind == InputKind::File && input.is_dir());
            if mismatched {
                self.input_path.clear();
                self.output_path.clear();
            } else {
                self.refresh_output_suggestion();
            }
        }

        if !self.busy() {
            self.set_status(StatusTone::Idle, self.default_status());
        }
    }

    fn set_compression_preset(&mut self, preset: CompressionPreset) {
        self.compression_preset = preset;
        if !self.compression_advanced {
            let compression = preset.folder_compression();
            self.compression_method = compression.method;
            self.compression_level = compression.level.unwrap_or(0);
        }
        if !self.busy() {
            self.set_status(StatusTone::Idle, self.default_status());
        }
    }

    fn toggle_compression_advanced(&mut self) {
        self.compression_advanced = !self.compression_advanced;
        if self.compression_advanced {
            let compression = self.compression_preset.folder_compression();
            self.compression_method = compression.method;
            self.compression_level = compression.level.unwrap_or(0);
        }
        if !self.busy() {
            self.set_status(StatusTone::Idle, self.default_status());
        }
    }

    fn set_compression_method(&mut self, method: FolderCompressionMethod) {
        self.compression_method = method;
        if method == FolderCompressionMethod::Stored {
            self.compression_level = 0;
        } else if self.compression_level == 0 {
            self.compression_level = 6;
        }
        if !self.busy() {
            self.set_status(StatusTone::Idle, self.default_status());
        }
    }

    fn set_profile(&mut self, profile: SecurityProfile) {
        self.profile = profile;
        if !self.busy() {
            self.set_status(StatusTone::Idle, self.default_status());
        }
    }

    fn set_language(&mut self, language: Language) {
        self.language = language;
        self.update_ui.apply_default_copy(language);
        if !self.busy() {
            self.set_status(StatusTone::Idle, self.default_status());
        }
    }

    fn apply_input_path(&mut self, path: PathBuf) {
        if is_supported_vault_path(&path) {
            self.mode = Mode::Decrypt;
            self.selected_payload_kind = inspect_vault(&path)
                .map(|summary| summary.payload_kind)
                .unwrap_or(PayloadKind::SingleFile);
        } else if path.is_dir() {
            self.mode = Mode::Encrypt;
            self.input_kind = InputKind::Folder;
            self.selected_payload_kind = PayloadKind::FolderArchive;
        } else {
            if self.mode == Mode::Encrypt {
                self.input_kind = InputKind::File;
            }
            self.selected_payload_kind = PayloadKind::SingleFile;
        }
        self.input_path = path.display().to_string();
        self.refresh_output_suggestion();
        self.remember_recent_input(self.input_path.clone());
        self.set_status(StatusTone::Idle, self.default_status());
        self.add_log(format!("{}: {}", self.tr("Input file", "입력 파일"), self.input_path));
    }

    fn browse_input(&mut self) {
        if self.mode == Mode::Encrypt && self.input_kind == InputKind::Folder {
            if let Some(path) = FileDialog::new().pick_folder() {
                self.apply_input_path(path);
            }
            return;
        }

        let dialog = match self.mode {
            Mode::Encrypt => FileDialog::new(),
            Mode::Decrypt => {
                FileDialog::new().add_filter("PillowLock Protected File", &[CUSTOM_EXTENSION, LEGACY_CUSTOM_EXTENSION])
            }
        };
        if let Some(paths) = dialog.pick_files() {
            if paths.len() == 1 {
                self.apply_input_path(paths[0].clone());
            } else if !paths.is_empty() {
                let mut added = 0usize;
                for path in paths {
                    if self
                        .enqueue_path(
                            &path,
                            self.mode,
                            self.profile,
                            Self::trimmed_path(&self.keyfile_path),
                            None,
                            InputKind::File,
                            None,
                        )
                        .is_ok()
                    {
                        added += 1;
                    }
                }
                self.show_queue = true;
                self.set_status(
                    StatusTone::Success,
                    format!("{} {added}", self.tr("Added files to the queue:", "큐에 파일을 추가했습니다:")),
                );
            }
        }
    }

    fn handle_dropped_file(&mut self, path: PathBuf) {
        self.drop_hovered = false;
        if !self.has_input_file() && self.queue_items.is_empty() {
            self.apply_input_path(path);
            self.set_status(StatusTone::Idle, self.tr("Input file added.", "입력 파일을 추가했습니다."));
            return;
        }
        let dropped_input_kind = if self.mode == Mode::Encrypt && path.is_dir() {
            InputKind::Folder
        } else {
            self.input_kind
        };
        let folder_compression = if self.mode == Mode::Encrypt && dropped_input_kind == InputKind::Folder {
            Some(self.effective_folder_compression())
        } else {
            None
        };
        if self
            .enqueue_path(
                &path,
                self.mode,
                self.profile,
                Self::trimmed_path(&self.keyfile_path),
                None,
                dropped_input_kind,
                folder_compression,
            )
            .is_ok()
        {
            self.show_queue = true;
            self.set_status(StatusTone::Success, self.tr("File added to the queue.", "파일을 큐에 추가했습니다."));
        }
    }

    fn browse_output(&mut self) {
        if self.output_target_is_directory() {
            let current_name = Self::trimmed_path(&self.output_path)
                .and_then(|path| path.file_name().map(|name| name.to_string_lossy().into_owned()))
                .unwrap_or_else(|| "restored-folder".to_owned());
            if let Some(parent) = FileDialog::new().pick_folder() {
                self.output_path = parent.join(current_name).display().to_string();
                self.set_status(StatusTone::Idle, self.tr("Output path updated.", "출력 경로를 업데이트했습니다."));
            }
            return;
        }
        let mut dialog = FileDialog::new();
        if let Some(path) = Self::trimmed_path(&self.output_path) {
            if let Some(name) = path.file_name().and_then(|name| name.to_str()) {
                dialog = dialog.set_file_name(name);
            }
        }
        if let Some(path) = dialog.save_file() {
            self.output_path = path.display().to_string();
            self.set_status(StatusTone::Idle, self.tr("Output path updated.", "출력 경로를 업데이트했습니다."));
        }
    }

    fn browse_keyfile(&mut self) {
        if let Some(path) = FileDialog::new().pick_file() {
            self.keyfile_path = path.display().to_string();
            let remembered = self.keyfile_path.clone();
            self.remember_session_keyfile(&remembered);
            self.set_status(StatusTone::Idle, self.tr("Key file selected.", "키 파일을 선택했습니다."));
        }
    }

    fn browse_new_keyfile(&mut self) {
        if let Some(path) = FileDialog::new().pick_file() {
            self.rotate_keyfile_path = path.display().to_string();
            let remembered = self.rotate_keyfile_path.clone();
            self.remember_session_keyfile(&remembered);
            self.set_status(StatusTone::Idle, self.tr("New key file selected.", "새 키 파일을 선택했습니다."));
        }
    }

    fn generate_keyfile_file(&mut self) {
        if self.busy() {
            return;
        }
        if let Some(path) = FileDialog::new()
            .add_filter("Key file", &["key", "bin"])
            .set_file_name("pillowlock.key")
            .save_file()
        {
            match generate_keyfile(&path) {
                Ok(()) => {
                    self.keyfile_path = path.display().to_string();
                    let remembered = self.keyfile_path.clone();
                    self.remember_session_keyfile(&remembered);
                    let message = self.tr("A new key file has been created.", "새 키 파일을 만들었습니다.");
                    self.set_status(StatusTone::Success, message);
                    self.add_log(format!(
                        "{}: {}",
                        self.tr("Key file created", "키 파일 생성"),
                        self.keyfile_path
                    ));
                }
                Err(error) => {
                    let message = error_to_text(&error, self.language);
                    self.set_status(StatusTone::Error, message.clone());
                    self.add_log(message);
                }
            }
        }
    }

    fn prepare_job(&mut self) -> Result<JobRequest, String> {
        if !self.can_start() {
            let message = self.readiness_hint().to_owned();
            self.set_status(StatusTone::Error, message.clone());
            return Err(message);
        }
        let input = Self::trimmed_path(&self.input_path)
            .ok_or_else(|| self.tr("Choose an input file.", "입력 파일을 선택하세요.").to_owned())?;
        let output = Self::trimmed_path(&self.output_path)
            .ok_or_else(|| self.tr("Choose where the result should be saved.", "결과 파일 위치를 정하세요.").to_owned())?;
        let keyfile = Self::trimmed_path(&self.keyfile_path);
        let input_kind = self.input_kind;
        let folder_compression = if self.mode == Mode::Encrypt && input_kind == InputKind::Folder {
            Some(self.effective_folder_compression())
        } else {
            None
        };
        let password = self.password.clone();
        self.clear_passwords();
        self.running = true;
        self.set_status(StatusTone::Working, self.tr("Running. Please wait for completion.", "작업 중입니다. 완료될 때까지 기다려주세요."));
        self.add_log(format!("{}: {} -> {}", self.mode_label(self.mode), input.display(), output.display()));
        Ok(JobRequest {
            input,
            output,
            keyfile,
            input_kind,
            folder_compression,
            language: self.language,
            mode: self.mode,
            profile: self.profile,
            password,
        })
    }

    fn prepare_verify(&mut self) -> Result<VerifyRequest, String> {
        if !self.can_verify() {
            let message = self
                .tr("Choose a protected file and enter its password.", "보호 파일을 선택하고 비밀번호를 입력하세요.")
                .to_owned();
            self.set_status(StatusTone::Error, message.clone());
            return Err(message);
        }
        let input = Self::trimmed_path(&self.input_path)
            .ok_or_else(|| self.tr("Choose a protected file.", "보호 파일을 선택하세요.").to_owned())?;
        let keyfile = Self::trimmed_path(&self.keyfile_path);
        let password = self.password.clone();
        self.clear_passwords();
        self.running = true;
        self.set_status(StatusTone::Working, self.tr("Verifying file integrity.", "보호 파일 무결성을 확인하고 있습니다."));
        Ok(VerifyRequest { input, keyfile, language: self.language, password })
    }

    fn prepare_rotate(&mut self) -> Result<RotateRequest, String> {
        if !self.can_rotate() {
            let message = self
                .tr("Choose input and output paths, then enter the current and new passwords.", "입력/출력 경로와 현재 및 새 비밀번호를 입력하세요.")
                .to_owned();
            self.set_status(StatusTone::Error, message.clone());
            return Err(message);
        }
        let input = Self::trimmed_path(&self.input_path)
            .ok_or_else(|| self.tr("Choose a protected file.", "보호 파일을 선택하세요.").to_owned())?;
        let output = Self::trimmed_path(&self.output_path).ok_or_else(|| {
            self.tr("Choose where the updated protected file should be saved.", "새 키로 갱신한 보호 파일 저장 위치를 정하세요.").to_owned()
        })?;
        let old_keyfile = Self::trimmed_path(&self.keyfile_path);
        let new_keyfile = Self::trimmed_path(&self.rotate_keyfile_path);
        let old_password = self.password.clone();
        let new_password = self.rotate_password.clone();
        self.clear_passwords();
        self.clear_rotate_passwords();
        self.running = true;
        self.set_status(StatusTone::Working, self.tr("Updating file keys.", "보호 파일 키를 교체하고 있습니다."));
        Ok(RotateRequest { input, output, old_keyfile, new_keyfile, language: self.language, old_password, new_password })
    }

    fn prepare_queue_run(&mut self) -> Result<QueueRunRequest, String> {
        if !self.can_queue_run() {
            let message = self.tr("Add pending jobs to the queue first.", "먼저 큐에 대기 작업을 추가하세요.").to_owned();
            self.set_status(StatusTone::Error, message.clone());
            return Err(message);
        }
        let pending_encrypt = self
            .queue_items
            .iter()
            .any(|item| item.status == QueueStatus::Pending && item.mode == Mode::Encrypt);
        if self.password_text().is_empty() {
            let message = self.tr("Enter a password before starting the queue.", "큐를 시작하기 전에 비밀번호를 입력하세요.").to_owned();
            self.set_status(StatusTone::Error, message.clone());
            return Err(message);
        }
        if pending_encrypt && self.password_text() != self.confirm_password_text() {
            let message = self.tr("Password confirmation must match before starting the queue.", "큐를 시작하기 전에 비밀번호 확인이 일치해야 합니다.").to_owned();
            self.set_status(StatusTone::Error, message.clone());
            return Err(message);
        }
        let items = self
            .queue_items
            .iter()
            .filter(|item| item.status == QueueStatus::Pending)
            .cloned()
            .collect::<Vec<_>>();
        let password = self.password.clone();
        self.clear_passwords();
        self.queue_cancel_flag.store(false, Ordering::Relaxed);
        self.queue_running = true;
        self.queue_stop_requested = false;
        self.current_queue_job = None;
        self.show_queue = true;
        self.set_status(StatusTone::Working, self.tr("Running queue jobs.", "배치 큐를 실행하고 있습니다."));
        Ok(QueueRunRequest { items, language: self.language, password, cancel_flag: self.queue_cancel_flag.clone() })
    }

    fn enqueue_current_form(&mut self) -> Result<(), String> {
        let input = Self::trimmed_path(&self.input_path)
            .ok_or_else(|| self.tr("Choose an input file first.", "먼저 입력 파일을 선택하세요.").to_owned())?;
        let output = Self::trimmed_path(&self.output_path)
            .ok_or_else(|| self.tr("Choose where the queued result should be saved.", "큐 작업의 출력 위치를 정하세요.").to_owned())?;
        let keyfile = Self::trimmed_path(&self.keyfile_path);
        let folder_compression = if self.mode == Mode::Encrypt && self.input_kind == InputKind::Folder {
            Some(self.effective_folder_compression())
        } else {
            None
        };
        self.enqueue_path(
            &input,
            self.mode,
            self.profile,
            keyfile,
            Some(output),
            self.input_kind,
            folder_compression,
        )?;
        self.show_queue = true;
        Ok(())
    }

    fn enqueue_path(
        &mut self,
        input: &Path,
        mode: Mode,
        profile: SecurityProfile,
        keyfile: Option<PathBuf>,
        output_override: Option<PathBuf>,
        input_kind: InputKind,
        folder_compression: Option<FolderCompression>,
    ) -> Result<(), String> {
        let payload_kind = match mode {
            Mode::Encrypt => {
                if input_kind == InputKind::Folder || input.is_dir() {
                    PayloadKind::FolderArchive
                } else {
                    PayloadKind::SingleFile
                }
            }
            Mode::Decrypt => inspect_vault(input)
                .map(|summary| summary.payload_kind)
                .unwrap_or(PayloadKind::SingleFile),
        };
        let output =
            output_override.unwrap_or_else(|| self.preferred_output_for(input, mode, payload_kind));
        let input_string = input.display().to_string();
        let output_string = output.display().to_string();
        if self
            .queue_items
            .iter()
            .any(|item| item.input_path == input_string && item.output_path == output_string && item.status == QueueStatus::Pending)
        {
            return Ok(());
        }
        let keyfile_path_session = keyfile.map(|path| path.display().to_string());
        if let Some(path) = keyfile_path_session.as_ref() {
            self.remember_session_keyfile(path);
        }
        let id = self.next_queue_job_id;
        self.next_queue_job_id += 1;
        self.queue_items.push(QueuedJob {
            id,
            mode,
            input_kind,
            payload_kind,
            input_path: input_string.clone(),
            output_path: output_string.clone(),
            keyfile_path_session,
            folder_compression,
            profile,
            status: QueueStatus::Pending,
            progress: 0,
            last_error: None,
        });
        self.selected_queue_job = Some(id);
        self.add_log(format!("{}: {} -> {}", self.tr("Queued", "큐 추가"), input_string, output_string));
        Ok(())
    }

    fn add_folder_to_queue(&mut self) {
        if self.busy() {
            return;
        }
        if let Some(folder) = FileDialog::new().pick_folder() {
            if self.mode == Mode::Encrypt && self.input_kind == InputKind::Folder {
                match self.enqueue_path(
                    &folder,
                    self.mode,
                    self.profile,
                    Self::trimmed_path(&self.keyfile_path),
                    None,
                    InputKind::Folder,
                    Some(self.effective_folder_compression()),
                ) {
                    Ok(()) => {
                        self.show_queue = true;
                        self.set_status(
                            StatusTone::Success,
                            self.tr("Folder added to the queue.", "폴더를 큐에 추가했습니다."),
                        );
                    }
                    Err(message) => self.set_status(StatusTone::Error, message),
                }
                return;
            }
            match collect_files_in_folder(&folder, self.queue_recursive, self.mode) {
                Ok(paths) if paths.is_empty() => {
                    self.set_status(StatusTone::Error, self.tr("No matching files were found in that folder.", "해당 폴더에서 조건에 맞는 파일을 찾지 못했습니다."));
                }
                Ok(paths) => {
                    let mut added = 0usize;
                    for path in paths {
                        if self
                            .enqueue_path(
                                &path,
                                self.mode,
                                self.profile,
                                Self::trimmed_path(&self.keyfile_path),
                                None,
                                InputKind::File,
                                None,
                            )
                            .is_ok()
                        {
                            added += 1;
                        }
                    }
                    self.show_queue = true;
                    self.set_status(StatusTone::Success, format!("{} {added}", self.tr("Folder items queued:", "폴더 항목을 큐에 추가했습니다:")));
                }
                Err(error) => {
                    self.set_status(StatusTone::Error, error.to_string());
                }
            }
        }
    }

    fn remove_selected_queue_item(&mut self) {
        let Some(selected) = self.selected_queue_job else {
            return;
        };
        if let Some(index) = self.queue_items.iter().position(|item| item.id == selected) {
            if self.queue_items[index].status == QueueStatus::Running {
                self.set_status(StatusTone::Error, self.tr("The running queue item cannot be removed.", "실행 중인 큐 항목은 제거할 수 없습니다."));
                return;
            }
            self.queue_items.remove(index);
            self.selected_queue_job = self.queue_items.last().map(|item| item.id);
            self.set_status(StatusTone::Idle, self.tr("Queue item removed.", "큐 항목을 제거했습니다."));
        }
    }

    fn retry_failed_jobs(&mut self) {
        let mut retried = 0usize;
        for item in &mut self.queue_items {
            if item.status == QueueStatus::Failed {
                item.status = QueueStatus::Pending;
                item.last_error = None;
                item.progress = 0;
                retried += 1;
            }
        }
        if retried > 0 {
            self.set_status(StatusTone::Idle, format!("{} {retried}", self.tr("Failed jobs reset:", "실패 작업 재설정:")));
        }
    }

    fn clear_finished_queue_items(&mut self) {
        self.queue_items.retain(|item| !item.status.is_finished() || item.status == QueueStatus::Running);
        self.selected_queue_job = self.queue_items.last().map(|item| item.id);
        self.set_status(StatusTone::Idle, self.tr("Completed queue items cleared.", "완료된 큐 항목을 정리했습니다."));
    }

    fn mark_queue_item_running(&mut self, id: u64) {
        self.current_queue_job = Some(id);
        if let Some(item) = self.queue_items.iter_mut().find(|item| item.id == id) {
            item.status = QueueStatus::Running;
            item.progress = 0;
            item.last_error = None;
        }
        self.selected_queue_job = Some(id);
    }

    fn finish_queue_item(&mut self, id: u64, result: Result<PathBuf, VaultError>, language: Language) {
        self.current_queue_job = None;
        let mut success_record: Option<(Mode, SecurityProfile, String, PathBuf)> = None;
        if let Some(item) = self.queue_items.iter_mut().find(|item| item.id == id) {
            match result {
                Ok(output) => {
                    item.status = QueueStatus::Success;
                    item.progress = 100;
                    item.last_error = None;
                    success_record = Some((item.mode, item.profile, item.input_path.clone(), output));
                }
                Err(VaultError::Cancelled) => {
                    item.status = QueueStatus::Cancelled;
                    item.progress = 0;
                    item.last_error = Some(error_to_text(&VaultError::Cancelled, language));
                }
                Err(error) => {
                    item.status = QueueStatus::Failed;
                    item.progress = 0;
                    item.last_error = Some(error_to_text(&error, language));
                }
            }
        }
        if let Some((mode, profile, input, output)) = success_record {
            self.record_success(mode, profile, Path::new(&input), &output);
            self.add_log(format!("{}: {}", self.tr("Queue item finished", "큐 작업 완료"), output.display()));
        }
    }

    fn finish_queue_run(&mut self) {
        if self.queue_stop_requested {
            let cancel_message = self
                .tr("Queue stopped before this item ran.", "큐가 이 항목 전에 중지됐습니다.")
                .to_owned();
            for item in &mut self.queue_items {
                if item.status == QueueStatus::Pending {
                    item.status = QueueStatus::Cancelled;
                    item.last_error = Some(cancel_message.clone());
                }
            }
            self.set_status(StatusTone::Success, self.tr("Queue stopped.", "큐를 중지했습니다."));
        } else {
            self.set_status(StatusTone::Success, self.tr("Queue finished.", "큐가 완료됐습니다."));
        }
        self.queue_running = false;
        self.queue_stop_requested = false;
        self.queue_cancel_flag.store(false, Ordering::Relaxed);
    }

    fn request_queue_cancel(&mut self) {
        if self.queue_running {
            self.queue_stop_requested = true;
            self.queue_cancel_flag.store(true, Ordering::Relaxed);
            self.set_status(StatusTone::Working, self.tr("Stopping after the current queue item.", "현재 큐 작업이 끝나는 대로 중지합니다."));
        }
    }

    fn quick_reopen_last_file(&mut self) {
        if let Some(path) = self.recent_inputs.first().cloned() {
            self.apply_input_path(PathBuf::from(path));
        }
    }

    fn quick_use_last_output_folder(&mut self) {
        if self.has_input_file() {
            self.refresh_output_suggestion();
            self.set_status(StatusTone::Idle, self.tr("Applied the last output folder.", "마지막 출력 폴더를 적용했습니다."));
        }
    }

    fn quick_repeat_last_setup(&mut self) {
        if let Some(mode) = self.last_success_mode {
            self.mode = mode;
        }
        if let Some(profile) = self.last_success_profile {
            self.profile = profile;
        }
        if self.has_input_file() {
            self.refresh_output_suggestion();
        }
        self.set_status(StatusTone::Idle, self.tr("Reused the last successful setup.", "마지막 성공 설정을 다시 적용했습니다."));
    }

    fn copy_last_output_path(&mut self) {
        let Some(path) = self.last_completed_output.clone() else {
            return;
        };
        match Clipboard::new().and_then(|mut clipboard| clipboard.set_text(path.clone())) {
            Ok(()) => self.set_status(StatusTone::Success, self.tr("Copied the result path.", "결과 경로를 복사했습니다.")),
            Err(error) => self.set_status(StatusTone::Error, error.to_string()),
        }
    }

    fn open_last_output_folder(&mut self) {
        let Some(path) = self.last_completed_output.as_ref().map(PathBuf::from) else {
            return;
        };
        let target = path.parent().map(PathBuf::from).unwrap_or(path);
        match Command::new("explorer.exe").arg(target).spawn() {
            Ok(_) => self.set_status(StatusTone::Success, self.tr("Opened the output folder.", "출력 폴더를 열었습니다.")),
            Err(error) => self.set_status(StatusTone::Error, error.to_string()),
        }
    }

    fn inspect_current_vault(&mut self) {
        let Some(path) = Self::trimmed_path(&self.input_path) else {
            self.set_status(StatusTone::Error, self.tr("Choose a file to inspect.", "검사할 파일을 선택하세요."));
            return;
        };
        let result = inspect_vault(&path);
        self.complete_inspect(&path, result);
    }

    fn remember_recent_input(&mut self, value: String) {
        push_recent_path(&mut self.recent_inputs, value);
    }

    fn remember_recent_output_folder(&mut self, value: String) {
        push_recent_path(&mut self.recent_output_folders, value);
    }

    fn record_success(&mut self, mode: Mode, profile: SecurityProfile, input: &Path, output: &Path) {
        let input_string = input.display().to_string();
        let output_string = output.display().to_string();
        self.last_completed_input = Some(input_string.clone());
        self.last_completed_output = Some(output_string.clone());
        self.last_success_mode = Some(mode);
        self.last_success_profile = Some(profile);
        self.remember_recent_input(input_string.clone());
        if let Some(parent) = output.parent() {
            let folder = parent.display().to_string();
            self.last_output_folder = Some(folder.clone());
            self.remember_recent_output_folder(folder);
        }
        push_recent_success(&mut self.recent_successes, RecentSuccess { mode, input_path: input_string, output_path: output_string, profile });
    }

    fn prune_recent_entries(&mut self) {
        self.recent_inputs.retain(|path| PathBuf::from(path).exists());
        self.recent_output_folders.retain(|path| PathBuf::from(path).is_dir());
        self.recent_successes.retain(|entry| {
            PathBuf::from(&entry.input_path).exists()
                || PathBuf::from(&entry.output_path)
                    .parent()
                    .map(|parent| parent.exists())
                    .unwrap_or(false)
        });
        self.recent_inputs.truncate(MAX_RECENT_ITEMS);
        self.recent_output_folders.truncate(MAX_RECENT_ITEMS);
        self.recent_successes.truncate(MAX_RECENT_ITEMS);
    }

    fn complete_job(&mut self, mode: Mode, input: PathBuf, profile: SecurityProfile, result: Result<PathBuf, String>) {
        self.running = false;
        match result {
            Ok(output) => {
                let message = match mode {
                    Mode::Encrypt => self.tr("Encryption completed successfully.", "암호화가 성공적으로 완료됐습니다."),
                    Mode::Decrypt => self.tr("Decryption completed successfully.", "복호화가 성공적으로 완료됐습니다."),
                };
                self.set_status(StatusTone::Success, message);
                self.record_success(mode, profile, &input, &output);
                self.add_log(format!("{}: {}", self.tr("Output saved", "저장 완료"), output.display()));
            }
            Err(message) => {
                self.set_status(StatusTone::Error, message.clone());
                self.add_log(message);
            }
        }
    }

    fn complete_verify(&mut self, result: Result<(), String>) {
        self.running = false;
        match result {
            Ok(()) => {
                self.set_status(StatusTone::Success, self.tr("File verification succeeded.", "보호 파일 검증이 성공했습니다."));
                self.advanced_tool_output = self
                    .tr("Verified: header and all chunks authenticated successfully.", "검증 완료: 헤더와 모든 청크 인증이 성공했습니다.")
                    .to_owned();
                self.add_log(self.advanced_tool_output.clone());
            }
            Err(message) => {
                self.set_status(StatusTone::Error, message.clone());
                self.advanced_tool_output = message.clone();
                self.add_log(message);
            }
        }
    }

    fn complete_rotate(&mut self, result: Result<PathBuf, String>) {
        self.running = false;
        match result {
            Ok(output) => {
                self.set_status(StatusTone::Success, self.tr("Key rotation completed.", "키 교체가 완료됐습니다."));
                self.advanced_tool_output = format!(
                    "{}\n{}",
                    self.tr("A new protected-file header was written successfully.", "새 보호 파일 헤더를 성공적으로 기록했습니다."),
                    output.display()
                );
                self.last_completed_output = Some(output.display().to_string());
                self.add_log(self.advanced_tool_output.clone());
            }
            Err(message) => {
                self.set_status(StatusTone::Error, message.clone());
                self.advanced_tool_output = message.clone();
                self.add_log(message);
            }
        }
    }

    /*
    fn prepare_update_check(&mut self) -> Result<UpdateCheckRequest, String> {
        let Some(repo_slug) = self.update_ui.repo_slug.clone() else {
            self.update_ui.apply_default_copy(self.language);
            return Err(self.update_ui.status_line.clone());
        };
        self.update_ui.checking = true;
        self.update_ui.status_line = self
            .tr("Checking GitHub releases…", "GitHub 릴리스를 확인하는 중입니다.")
            .to_owned();
        self.update_ui.details = format!(
            "{}: {APP_VERSION}\n{}: {}",
            self.tr("Current version", "현재 버전"),
            self.tr("Repository", "저장소"),
            repo_slug
        );
        Ok(UpdateCheckRequest { repo_slug })
    }

    */
    fn prepare_update_check(&mut self) -> Result<UpdateCheckRequest, String> {
        let Some(repo_slug) = self.update_ui.repo_slug.clone() else {
            self.update_ui.apply_default_copy(self.language);
            return Err(self.update_ui.status_line.clone());
        };
        self.update_ui.checking = true;
        self.update_ui.status_line = self
            .tr("Checking GitHub releases...", "GitHub 릴리스를 확인하는 중입니다.")
            .to_owned();
        self.update_ui.details = format!(
            "{}: {APP_VERSION}\n{}: {}",
            self.tr("Current version", "현재 버전"),
            self.tr("Repository", "저장소"),
            repo_slug
        );
        Ok(UpdateCheckRequest { repo_slug })
    }

    fn complete_update_check(&mut self, result: Result<UpdateReleaseInfo, String>) {
        self.update_ui.checking = false;
        self.update_ui.checked_once = true;
        match result {
            Ok(info) => {
                self.update_ui.available = info.available;
                self.update_ui.latest_version = Some(info.version.clone());
                self.update_ui.release_url = Some(info.release_url.clone());
                self.update_ui.download_url = info.download_url.clone();
                self.update_ui.download_asset_name = info.asset_name.clone();
                if info.available {
                    self.update_ui.status_line = self.tr("Update available.", "업데이트가 있습니다.").to_owned();
                    self.update_ui.details = format!(
                        "{}: {APP_VERSION}\n{}: {}\n{}: {}\n{}",
                        self.tr("Current version", "현재 버전"),
                        self.tr("Latest version", "최신 버전"),
                        info.version,
                        self.tr("Repository", "저장소"),
                        info.repo_slug,
                        match (&info.asset_name, &info.release_notes_excerpt) {
                            (Some(asset), Some(notes)) => format!(
                                "{}: {asset}\n{}: {notes}",
                                self.tr("Installer asset", "설치 파일"),
                                self.tr("Release notes", "릴리스 노트")
                            ),
                            (Some(asset), None) => format!(
                                "{}: {asset}",
                                self.tr("Installer asset", "설치 파일")
                            ),
                            (None, Some(notes)) => format!(
                                "{}\n{}: {notes}",
                                self.tr("No installer asset was attached to the latest release.", "최신 릴리스에 설치 파일이 첨부되지 않았습니다."),
                                self.tr("Release notes", "릴리스 노트")
                            ),
                            (None, None) => self
                                .tr(
                                    "Open the release page to download the installer manually.",
                                    "릴리스 페이지를 열어 설치 파일을 직접 내려받으세요.",
                                )
                                .to_owned(),
                        }
                    );
                    self.add_log(format!(
                        "{} {}",
                        self.tr("Update available:", "업데이트 가능:"),
                        info.tag_name
                    ));
                } else {
                    self.update_ui.status_line = self.tr("You are up to date.", "최신 버전을 사용 중입니다.").to_owned();
                    self.update_ui.details = format!(
                        "{}: {APP_VERSION}\n{}: {}\n{}: {}",
                        self.tr("Current version", "현재 버전"),
                        self.tr("Latest version", "최신 버전"),
                        info.version,
                        self.tr("Repository", "저장소"),
                        info.repo_slug
                    );
                    self.add_log(format!(
                        "{} {}",
                        self.tr("Update check complete:", "업데이트 확인 완료:"),
                        info.tag_name
                    ));
                }
            }
            Err(message) => {
                self.update_ui.available = false;
                self.update_ui.download_url = None;
                self.update_ui.download_asset_name = None;
                self.update_ui.status_line = self.tr("Update check failed.", "업데이트 확인에 실패했습니다.").to_owned();
                self.update_ui.details = message.clone();
                self.add_log(message);
            }
        }
    }

    /*
    fn prepare_update_install(&mut self) -> Result<UpdateInstallRequest, String> {
        let Some(download_url) = self.update_ui.download_url.clone() else {
            let message = self
                .tr(
                    "No downloadable installer is attached to the latest release.",
                    "최신 릴리스에 내려받을 설치 파일이 없습니다.",
                )
                .to_owned();
            self.update_ui.status_line = self.tr("Installer unavailable.", "설치 파일이 없습니다.").to_owned();
            self.update_ui.details = message.clone();
            return Err(message);
        };
        let asset_name = self
            .update_ui
            .download_asset_name
            .clone()
            .unwrap_or_else(|| format!("PillowLock-{}-x64.msi", self.update_ui.latest_version.clone().unwrap_or_else(|| APP_VERSION.to_owned())));
        self.update_ui.checking = true;
        self.update_ui.status_line = self
            .tr("Downloading installer…", "설치 파일을 다운로드하는 중입니다.")
            .to_owned();
        self.update_ui.details = format!(
            "{}: {asset_name}\n{}",
            self.tr("Installer asset", "설치 파일"),
            self.tr(
                "PillowLock will launch the installer when the download finishes.",
                "다운로드가 끝나면 PillowLock이 설치 프로그램을 실행합니다.",
            )
        );
        Ok(UpdateInstallRequest { download_url, asset_name })
    }

    */
    fn prepare_update_install(&mut self) -> Result<UpdateInstallRequest, String> {
        let Some(download_url) = self.update_ui.download_url.clone() else {
            let message = self
                .tr(
                    "No downloadable installer is attached to the latest release.",
                    "최신 릴리스에 내려받을 설치 파일이 없습니다.",
                )
                .to_owned();
            self.update_ui.status_line = self.tr("Installer unavailable.", "설치 파일이 없습니다.").to_owned();
            self.update_ui.details = message.clone();
            return Err(message);
        };
        let asset_name = self.update_ui.download_asset_name.clone().unwrap_or_else(|| {
            format!(
                "PillowLock-{}-setup-x64.exe",
                self.update_ui
                    .latest_version
                    .clone()
                    .unwrap_or_else(|| APP_VERSION.to_owned())
            )
        });
        self.update_ui.checking = true;
        self.update_ui.status_line = self
            .tr("Downloading installer...", "설치 파일을 다운로드하는 중입니다.")
            .to_owned();
        self.update_ui.details = format!(
            "{}: {asset_name}\n{}",
            self.tr("Installer asset", "설치 파일"),
            self.tr(
                "PillowLock will launch the installer when the download finishes.",
                "다운로드가 끝나면 PillowLock이 설치 프로그램을 실행합니다.",
            )
        );
        Ok(UpdateInstallRequest { download_url, asset_name })
    }

    fn complete_update_install(&mut self, result: Result<PathBuf, String>) {
        self.update_ui.checking = false;
        match result {
            Ok(path) => {
                self.update_ui.status_line = self
                    .tr("Installer launched.", "설치 프로그램을 실행했습니다.")
                    .to_owned();
                self.update_ui.details = format!(
                    "{}\n{}: {}",
                    self.tr(
                        "Close PillowLock if Windows asks before completing the update.",
                        "Windows가 요청하면 PillowLock을 닫고 업데이트를 진행하세요.",
                    ),
                    self.tr("Downloaded file", "다운로드 파일"),
                    path.display()
                );
                self.add_log(format!(
                    "{} {}",
                    self.tr("Installer started:", "설치 시작:"),
                    path.display()
                ));
            }
            Err(message) => {
                self.update_ui.status_line = self
                    .tr("Installer launch failed.", "설치 프로그램 실행에 실패했습니다.")
                    .to_owned();
                self.update_ui.details = message.clone();
                self.add_log(message);
            }
        }
    }

    fn open_release_page(&mut self) {
        let Some(url) = self.update_ui.release_url.clone() else {
            return;
        };
        match Command::new("explorer.exe").arg(&url).spawn() {
            Ok(_) => {
                self.update_ui.status_line = self
                    .tr("Release page opened.", "릴리스 페이지를 열었습니다.")
                    .to_owned();
                self.update_ui.details = format!(
                    "{}\n{}",
                    self.tr("Opened the latest GitHub release page in your browser.", "브라우저에서 최신 GitHub 릴리스 페이지를 열었습니다."),
                    url
                );
                self.add_log(format!(
                    "{} {}",
                    self.tr("Release page opened:", "릴리스 페이지 열기:"),
                    url
                ));
            }
            Err(error) => {
                self.update_ui.status_line = self
                    .tr("Could not open the release page.", "릴리스 페이지를 열 수 없습니다.")
                    .to_owned();
                self.update_ui.details = error.to_string();
            }
        }
    }

    fn complete_inspect(&mut self, path: &Path, result: Result<VaultSummary, VaultError>) {
        match result {
            Ok(summary) => {
                self.set_status(StatusTone::Success, self.tr("File summary loaded.", "보호 파일 요약을 불러왔습니다."));
                self.advanced_tool_output = format_vault_summary(&summary, self.language);
                self.add_log(format!("{}: {}", self.tr("Inspect", "검사"), path.display()));
            }
            Err(error) => {
                let message = error_to_text(&error, self.language);
                self.set_status(StatusTone::Error, message.clone());
                self.advanced_tool_output = message.clone();
                self.add_log(message);
            }
        }
    }

    fn queue_summary(&self) -> String {
        let pending = self.queue_items.iter().filter(|item| item.status == QueueStatus::Pending).count();
        let running = self.queue_items.iter().filter(|item| item.status == QueueStatus::Running).count();
        let success = self.queue_items.iter().filter(|item| item.status == QueueStatus::Success).count();
        let failed = self.queue_items.iter().filter(|item| item.status == QueueStatus::Failed).count();
        let cancelled = self.queue_items.iter().filter(|item| item.status == QueueStatus::Cancelled).count();
        format!(
            "{} {}\n{} {}\n{} {}\n{} {}\n{} {}",
            self.tr("Pending", "대기"), pending,
            self.tr("Running", "진행 중"), running,
            self.tr("Succeeded", "성공"), success,
            self.tr("Failed", "실패"), failed,
            self.tr("Cancelled", "취소"), cancelled,
        )
    }

    fn queue_display_rows(&self) -> Vec<SharedString> {
        self.queue_items
            .iter()
            .map(|item| {
                let item_kind = match item.mode {
                    Mode::Encrypt => self.input_kind_label(item.input_kind),
                    Mode::Decrypt => self.payload_kind_label(item.payload_kind),
                };
                SharedString::from(format!(
                    "[{}] {} | {} | {} -> {}{}",
                    self.queue_status_label(item.status),
                    self.mode_label(item.mode),
                    item_kind,
                    short_name(&item.input_path, self.language),
                    short_name(&item.output_path, self.language),
                    item.last_error.as_ref().map(|err| format!(" | {err}")).unwrap_or_default()
                ))
            })
            .collect()
    }

    fn selected_queue_index(&self) -> i32 {
        self.selected_queue_job
            .and_then(|selected| self.queue_items.iter().position(|item| item.id == selected).map(|index| index as i32))
            .unwrap_or(-1)
    }

    fn select_queue_index(&mut self, index: i32) {
        if index < 0 {
            self.selected_queue_job = None;
            return;
        }
        self.selected_queue_job = self.queue_items.get(index as usize).map(|item| item.id);
    }

    fn selection_details(&self) -> String {
        format!(
            "{}: {}\n{}: {}\n{}: {}\n{}: {}\n{}: {}",
            self.tr("Mode", "모드"),
            self.mode_label(self.mode),
            self.tr("Profile", "프로필"),
            self.profile_label(self.profile),
            self.tr("Input", "입력"),
            short_name(&self.input_path, self.language),
            self.tr("Output", "출력"),
            short_name(&self.output_path, self.language),
            self.tr("Key file", "키 파일"),
            short_name(&self.keyfile_path, self.language),
        )
    }

    fn security_details(&self) -> String {
        let config = self.profile.config();
        let hierarchy = if self.keyfile_path.trim().is_empty() {
            self.tr("Password-derived wrap key", "비밀번호 기반 래핑 키")
        } else {
            self.tr("Password + key file bound wrap key", "비밀번호 + 키 파일 결합 래핑 키")
        };
        format!(
            "{}: PillowLock v4\n{}: {}\n{}: AES-256-GCM\n{}: {}\n{}: Argon2id {} MiB\n{}: {}\n{}: {} MiB",
            self.tr("Format", "형식"),
            self.tr("Compatibility", "호환성"),
            self.tr("Reads v1-v4", "v1-v4 읽기 지원"),
            self.tr("Cipher", "암호"),
            self.tr("Key hierarchy", "키 계층"),
            hierarchy,
            self.tr("Memory", "메모리"),
            config.argon_memory_kib / 1024,
            self.tr("Iterations", "반복"),
            config.argon_iterations,
            self.tr("Chunk size", "청크 크기"),
            config.chunk_size / 1024 / 1024,
        )
    }

    fn activity_details(&self) -> String {
        if self.logs.is_empty() {
            return self.tr("No recent activity.", "최근 활동이 없습니다.").to_owned();
        }
        self.logs
            .iter()
            .rev()
            .take(10)
            .cloned()
            .collect::<Vec<_>>()
            .into_iter()
            .rev()
            .collect::<Vec<_>>()
            .join("\n")
    }

    fn recent_inputs_text(&self) -> String {
        summary_list(
            &self.recent_inputs,
            self.language,
            self.tr(
                "No recent file yet. Drop a file below to start protecting or restoring one.",
                "아직 최근 파일이 없습니다. 아래에 파일을 끌어다 놓고 바로 시작해 보세요.",
            ),
        )
    }

    fn recent_outputs_text(&self) -> String {
        summary_list(
            &self.recent_output_folders,
            self.language,
            self.tr(
                "No recent output folder yet. Once a task finishes, your favorite save locations show up here.",
                "아직 최근 출력 폴더가 없습니다. 작업이 끝나면 자주 쓰는 저장 위치가 여기에 표시됩니다.",
            ),
        )
    }

    fn recent_jobs_text(&self) -> String {
        if self.recent_successes.is_empty() {
            return self
                .tr(
                    "No completed task yet. Your latest successful protected-file or restore task will appear here.",
                    "아직 완료된 작업이 없습니다. 최근에 성공한 보호 파일 작업이나 복원 작업이 여기에 표시됩니다.",
                )
                .to_owned();
        }
        self.recent_successes
            .iter()
            .take(5)
            .map(|entry| format!("{} | {}", self.mode_label(entry.mode), short_name(&entry.input_path, self.language)))
            .collect::<Vec<_>>()
            .join("\n")
    }
}

fn settings_path() -> Option<PathBuf> {
    env::var_os("LOCALAPPDATA")
        .map(PathBuf::from)
        .map(|base| base.join("PillowLock").join("settings.json"))
}

fn configured_update_repo() -> Option<String> {
    option_env!("PILLOWLOCK_UPDATE_REPO")
        .map(str::to_owned)
        .or_else(|| env::var("PILLOWLOCK_UPDATE_REPO").ok())
        .map(|value| value.trim().trim_matches('/').to_owned())
        .filter(|value| !value.is_empty())
}

fn load_settings() -> AppState {
    settings_path()
        .and_then(|path| fs::read(path).ok())
        .and_then(|bytes| serde_json::from_slice::<PersistedSettings>(&bytes).ok())
        .map(AppState::from_settings)
        .unwrap_or_default()
}

fn parse_semver_components(value: &str) -> Option<Vec<u64>> {
    let core = value
        .trim()
        .trim_start_matches(|ch| ch == 'v' || ch == 'V')
        .split(['-', '+'])
        .next()?;
    let mut parts = Vec::new();
    for piece in core.split('.') {
        parts.push(piece.parse::<u64>().ok()?);
    }
    while parts.len() < 3 {
        parts.push(0);
    }
    Some(parts)
}

fn is_newer_version(latest: &str, current: &str) -> Option<bool> {
    let latest = parse_semver_components(latest)?;
    let current = parse_semver_components(current)?;
    let max_len = latest.len().max(current.len());
    for index in 0..max_len {
        let left = *latest.get(index).unwrap_or(&0);
        let right = *current.get(index).unwrap_or(&0);
        match left.cmp(&right) {
            std::cmp::Ordering::Greater => return Some(true),
            std::cmp::Ordering::Less => return Some(false),
            std::cmp::Ordering::Equal => {}
        }
    }
    Some(false)
}

fn normalize_release_version(tag_name: &str) -> String {
    tag_name.trim().trim_start_matches(|ch| ch == 'v' || ch == 'V').to_owned()
}

fn release_notes_excerpt(body: Option<String>) -> Option<String> {
    body.and_then(|body| {
        body.lines()
            .map(str::trim)
            .find(|line| !line.is_empty())
            .map(|line| {
                let mut value = line.to_owned();
                if value.chars().count() > 180 {
                    value = value.chars().take(180).collect::<String>() + "...";
                }
                value
            })
    })
}

fn pick_installer_asset(assets: &[GitHubReleaseAsset]) -> Option<&GitHubReleaseAsset> {
    assets
        .iter()
        .find(|asset| asset.name.eq_ignore_ascii_case("setup.exe") || asset.name.to_ascii_lowercase().ends_with("-setup-x64.exe"))
        .or_else(|| assets.iter().find(|asset| asset.name.to_ascii_lowercase().ends_with(".msi")))
}

fn run_curl_capture(args: &[String]) -> Result<Vec<u8>, String> {
    let output = Command::new("curl.exe")
        .args(args)
        .output()
        .map_err(|error| format!("Failed to start curl.exe: {error}"))?;
    if output.status.success() {
        return Ok(output.stdout);
    }
    let stderr = String::from_utf8_lossy(&output.stderr).trim().to_owned();
    let stdout = String::from_utf8_lossy(&output.stdout).trim().to_owned();
    Err(if !stderr.is_empty() {
        stderr
    } else if !stdout.is_empty() {
        stdout
    } else {
        format!("curl.exe exited with status {}", output.status)
    })
}

fn fetch_latest_release_info(repo_slug: &str) -> Result<UpdateReleaseInfo, String> {
    let url = format!("{GITHUB_RELEASES_API_ROOT}/{repo_slug}/releases/latest");
    let args = vec![
        "-fsSL".to_owned(),
        "-H".to_owned(),
        format!("User-Agent: PillowLock/{APP_VERSION}"),
        "-H".to_owned(),
        "Accept: application/vnd.github+json".to_owned(),
        url,
    ];
    let response_bytes = run_curl_capture(&args)?;
    let release: GitHubReleaseResponse = serde_json::from_slice(&response_bytes)
        .map_err(|error| format!("Could not parse GitHub release metadata: {error}"))?;
    let version = normalize_release_version(&release.tag_name);
    let available = is_newer_version(&version, APP_VERSION).unwrap_or(version != APP_VERSION);
    let chosen_asset = pick_installer_asset(&release.assets);
    Ok(UpdateReleaseInfo {
        repo_slug: repo_slug.to_owned(),
        tag_name: release.tag_name,
        version,
        release_url: release.html_url,
        download_url: chosen_asset.map(|asset| asset.browser_download_url.clone()),
        asset_name: chosen_asset.map(|asset| asset.name.clone()),
        release_notes_excerpt: release_notes_excerpt(release.body),
        available,
    })
}

fn download_and_launch_installer(download_url: &str, asset_name: &str) -> Result<PathBuf, String> {
    let mut download_dir = env::temp_dir();
    download_dir.push(UPDATE_DOWNLOAD_DIR);
    fs::create_dir_all(&download_dir).map_err(|error| format!("Could not create the update download folder: {error}"))?;
    let target_path = download_dir.join(asset_name);
    let args = vec![
        "-fL".to_owned(),
        "-H".to_owned(),
        format!("User-Agent: PillowLock/{APP_VERSION}"),
        "-o".to_owned(),
        target_path.display().to_string(),
        download_url.to_owned(),
    ];
    run_curl_capture(&args).map(|_| ())?;
    let extension = target_path
        .extension()
        .and_then(|ext| ext.to_str())
        .map(|ext| ext.to_ascii_lowercase())
        .unwrap_or_default();
    let spawn_result = if extension == "msi" {
        Command::new("msiexec.exe").arg("/i").arg(&target_path).spawn()
    } else {
        Command::new(&target_path).spawn()
    };
    spawn_result
        .map_err(|error| format!("Could not launch the installer: {error}"))?;
    Ok(target_path)
}

fn push_recent_path(list: &mut Vec<String>, value: String) {
    if value.trim().is_empty() {
        return;
    }
    list.retain(|item| item != &value);
    list.insert(0, value);
    list.truncate(MAX_RECENT_ITEMS);
}

fn push_recent_success(list: &mut Vec<RecentSuccess>, value: RecentSuccess) {
    list.retain(|item| item.input_path != value.input_path || item.output_path != value.output_path);
    list.insert(0, value);
    list.truncate(MAX_RECENT_ITEMS);
}

fn summary_list(items: &[String], language: Language, empty_text: &str) -> String {
    if items.is_empty() {
        return empty_text.to_owned();
    }
    items
        .iter()
        .take(5)
        .map(|item| short_name(item, language))
        .collect::<Vec<_>>()
        .join("\n")
}

fn short_name(value: &str, language: Language) -> String {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return match language {
            Language::English => "Not selected".to_owned(),
            Language::Korean => "선택 안 됨".to_owned(),
        };
    }
    PathBuf::from(trimmed)
        .file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_else(|| trimmed.to_owned())
}

fn is_supported_vault_path(path: &Path) -> bool {
    path.extension()
        .and_then(|ext| ext.to_str())
        .map(|ext| ext.eq_ignore_ascii_case(CUSTOM_EXTENSION) || ext.eq_ignore_ascii_case(LEGACY_CUSTOM_EXTENSION))
        .unwrap_or(false)
}

fn collect_files_in_folder(folder: &Path, recursive: bool, mode: Mode) -> std::io::Result<Vec<PathBuf>> {
    let mut files = Vec::new();
    collect_files_inner(folder, recursive, mode, &mut files)?;
    Ok(files)
}

fn collect_files_inner(folder: &Path, recursive: bool, mode: Mode, files: &mut Vec<PathBuf>) -> std::io::Result<()> {
    for entry in fs::read_dir(folder)? {
        let entry = entry?;
        let path = entry.path();
        let file_type = entry.file_type()?;
        if file_type.is_dir() && recursive {
            collect_files_inner(&path, recursive, mode, files)?;
        } else if file_type.is_file() {
            let should_include = match mode {
                Mode::Encrypt => !is_supported_vault_path(&path),
                Mode::Decrypt => is_supported_vault_path(&path),
            };
            if should_include {
                files.push(path);
            }
        }
    }
    Ok(())
}

fn format_vault_summary(summary: &VaultSummary, language: Language) -> String {
    match language {
        Language::English => format!(
            "Version: {}\nPayload: {}\nCipher: {}\nKDF: {}\nKey wrap: {}\nKey file required: {}\nChunk size: {} MiB\nArgon memory: {} MiB\nArgon iterations: {}\nArgon lanes: {}\nSupports key rotation: {}",
            summary.version,
            match summary.payload_kind {
                PayloadKind::SingleFile => "single file",
                PayloadKind::FolderArchive => "folder archive",
            },
            summary.cipher,
            summary.kdf,
            summary.key_wrap,
            if summary.keyfile_required { "yes" } else { "no" },
            summary.chunk_size / 1024 / 1024,
            summary.argon_memory_kib / 1024,
            summary.argon_iterations,
            summary.argon_lanes,
            if summary.supports_rewrap { "yes" } else { "no" },
        ),
        Language::Korean => format!(
            "버전: {}\n페이로드: {}\n암호: {}\nKDF: {}\n키 래핑: {}\n키 파일 필요: {}\n청크 크기: {} MiB\nArgon 메모리: {} MiB\nArgon 반복: {}\nArgon 레인: {}\n키 교체 지원: {}",
            summary.version,
            match summary.payload_kind {
                PayloadKind::SingleFile => "단일 파일",
                PayloadKind::FolderArchive => "폴더 아카이브",
            },
            summary.cipher,
            summary.kdf,
            summary.key_wrap,
            if summary.keyfile_required { "예" } else { "아니오" },
            summary.chunk_size / 1024 / 1024,
            summary.argon_memory_kib / 1024,
            summary.argon_iterations,
            summary.argon_lanes,
            if summary.supports_rewrap { "예" } else { "아니오" },
        ),
    }
}

fn error_to_text(error: &VaultError, language: Language) -> String {
    match error {
        VaultError::InvalidInputPath => match language {
            Language::English => "The input path does not exist or is not a regular file.".to_owned(),
            Language::Korean => "입력 경로가 없거나 일반 파일이 아닙니다.".to_owned(),
        },
        VaultError::InvalidKeyfilePath => match language {
            Language::English => "The key file path does not exist or is not a regular file.".to_owned(),
            Language::Korean => "키 파일 경로가 없거나 일반 파일이 아닙니다.".to_owned(),
        },
        VaultError::KeyfileTooLarge(size) => match language {
            Language::English => format!("Key files larger than 10 MiB are not allowed.\nCurrent size: {size} bytes"),
            Language::Korean => format!("키 파일은 10 MiB를 초과할 수 없습니다.\n현재 크기: {size} bytes"),
        },
        VaultError::OutputExists(path) => match language {
            Language::English => format!("The output file already exists.\n{path}"),
            Language::Korean => format!("출력 파일이 이미 존재합니다.\n{path}"),
        },
        VaultError::EmptyPassword => match language {
            Language::English => "Password cannot be empty.".to_owned(),
            Language::Korean => "비밀번호는 비워둘 수 없습니다.".to_owned(),
        },
        VaultError::KeyfileRequired => match language {
            Language::English => "This protected file requires a key file.".to_owned(),
            Language::Korean => "이 보호 파일은 키 파일이 필요합니다.".to_owned(),
        },
        VaultError::InvalidConfiguration(message) => match language {
            Language::English => format!("The security configuration is invalid.\n{message}"),
            Language::Korean => format!("보안 설정이 올바르지 않습니다.\n{message}"),
        },
        VaultError::InvalidFormat => match language {
            Language::English => "The protected-file format is invalid or appears to be damaged.".to_owned(),
            Language::Korean => "보호 파일 형식이 잘못됐거나 손상된 것으로 보입니다.".to_owned(),
        },
        VaultError::UnsupportedVersion(version) => match language {
            Language::English => format!("This protected-file version is not supported.\n{version}"),
            Language::Korean => format!("지원하지 않는 보호 파일 버전입니다.\n{version}"),
        },
        VaultError::UnsupportedPayloadKind(kind) => match language {
            Language::English => format!("This protected payload type is not supported.\n{kind}"),
            Language::Korean => format!("지원하지 않는 페이로드 형식입니다.\n{kind}"),
        },
        VaultError::UnsupportedRewrapVersion(version) => match language {
            Language::English => format!("Key rotation is not supported for this protected-file version.\n{version}"),
            Language::Korean => format!("이 보호 파일 버전은 키 교체를 지원하지 않습니다.\n{version}"),
        },
        VaultError::UnsupportedRewrapLayout => match language {
            Language::English => "This protected file uses a legacy v4 layout and cannot be rewrapped in place.".to_owned(),
            Language::Korean => "이 보호 파일은 이전 v4 레이아웃이라 같은 내용 그대로 키 교체를 할 수 없습니다.".to_owned(),
        },
        VaultError::UnsupportedAlgorithms => match language {
            Language::English => "This combination of algorithms is not supported.".to_owned(),
            Language::Korean => "이 알고리즘 조합은 지원하지 않습니다.".to_owned(),
        },
        VaultError::AuthenticationFailed => match language {
            Language::English => "Authentication failed. Check the password, key file, or file integrity.".to_owned(),
            Language::Korean => "인증에 실패했습니다. 비밀번호, 키 파일, 파일 무결성을 확인하세요.".to_owned(),
        },
        VaultError::Cancelled => match language {
            Language::English => "The operation was cancelled.".to_owned(),
            Language::Korean => "작업이 취소됐습니다.".to_owned(),
        },
        VaultError::Io(error) => match language {
            Language::English => format!("A file I/O error occurred.\n{error}"),
            Language::Korean => format!("파일 입출력 오류가 발생했습니다.\n{error}"),
        },
        VaultError::KeyDerivation(error) => match language {
            Language::English => format!("A key derivation error occurred.\n{error}"),
            Language::Korean => format!("키 파생 오류가 발생했습니다.\n{error}"),
        },
        VaultError::KeyExpansion => match language {
            Language::English => "An error occurred while expanding key material.".to_owned(),
            Language::Korean => "키 재료를 확장하는 중 오류가 발생했습니다.".to_owned(),
        },
        VaultError::EncryptionFailure => match language {
            Language::English => "An error occurred during encryption or decryption.".to_owned(),
            Language::Korean => "암호화 또는 복호화 중 오류가 발생했습니다.".to_owned(),
        },
        VaultError::NoParentDirectory => match language {
            Language::English => "The output path must have an existing parent directory.".to_owned(),
            Language::Korean => "출력 경로에는 존재하는 상위 폴더가 필요합니다.".to_owned(),
        },
        VaultError::SameInputAndOutput => match language {
            Language::English => "Input and output paths must be different.".to_owned(),
            Language::Korean => "입력 경로와 출력 경로는 달라야 합니다.".to_owned(),
        },
        VaultError::TooManyChunks => match language {
            Language::English => "The file is too large to process with the current format.".to_owned(),
            Language::Korean => "현재 형식으로 처리하기에는 파일이 너무 큽니다.".to_owned(),
        },
        VaultError::FileTooLarge => match language {
            Language::English => "The file exceeds the size limit of the current format.".to_owned(),
            Language::Korean => "파일이 현재 형식의 크기 제한을 초과했습니다.".to_owned(),
        },
        VaultError::Archive(message) => match language {
            Language::English => format!("The folder archive could not be processed.\n{message}"),
            Language::Korean => format!("폴더 아카이브를 처리할 수 없습니다.\n{message}"),
        },
    }
}

fn pull_form_fields(window: &AppWindow, state: &mut AppState) {
    state.output_path = window.get_output_path().to_string();
    state.keyfile_path = window.get_keyfile_path().to_string();
    state.password = secret_from_string(window.get_password().to_string());
    state.confirm_password = secret_from_string(window.get_confirm_password().to_string());
    state.rotate_password = secret_from_string(window.get_rotate_password().to_string());
    state.rotate_confirm_password = secret_from_string(window.get_rotate_confirm_password().to_string());
    state.rotate_keyfile_path = window.get_rotate_keyfile_path().to_string();
    let level_text = window.get_compression_level().to_string();
    if let Ok(level) = level_text.trim().parse::<i32>() {
        state.compression_level = level.clamp(0, 9);
    }
}

fn string_model(items: Vec<SharedString>) -> ModelRc<SharedString> {
    Rc::new(VecModel::from(items)).into()
}

fn sync_ui(window: &AppWindow, state: &AppState) {
    window.set_window_title(APP_TITLE.into());
    window.set_app_title(APP_TITLE.into());
    window.set_app_subtitle(state.tr("Layered file protection for desktop", "데스크톱용 계층형 파일 보호").into());
    window.set_encrypt_label(state.mode_label(Mode::Encrypt).into());
    window.set_decrypt_label(state.mode_label(Mode::Decrypt).into());
    window.set_balanced_label(state.profile_label(SecurityProfile::Balanced).into());
    window.set_hardened_label(state.profile_label(SecurityProfile::Hardened).into());
    window.set_english_label("EN".into());
    window.set_korean_label("KO".into());
    window.set_mode_group_title(state.tr("Choose a task", "작업 선택").into());
    window.set_mode_group_subtitle(
        state
            .tr(
                "Encrypt locks a regular file. Decrypt restores a .plock protected file back to a normal file.",
                "암호화는 일반 파일을 보호하고, 복호화는 .plock 보호 파일을 다시 일반 파일로 되돌립니다.",
            )
            .into(),
    );
    window.set_profile_group_title(state.tr("Choose a protection level", "보호 강도 선택").into());
    window.set_profile_group_subtitle(
        state
            .tr(
                "Balanced is faster for everyday use. Hardened spends more memory for tougher password defense.",
                "균형은 일상 작업에 더 빠르고, 강화는 더 많은 메모리로 비밀번호 방어를 높입니다.",
            )
            .into(),
    );
    window.set_advanced_label(state.tr(if state.show_advanced { "Hide details" } else { "Advanced" }, if state.show_advanced { "상세 숨기기" } else { "고급 정보" }).into());
    window.set_queue_panel_label(state.tr(if state.show_queue { "Hide queue" } else { "Queue" }, if state.show_queue { "큐 숨기기" } else { "큐" }).into());
    window.set_recursive_label(state.tr("Recursive", "하위 포함").into());
    window.set_encrypt_mode(state.mode == Mode::Encrypt);
    window.set_hardened_profile(state.profile == SecurityProfile::Hardened);
    window.set_english_language(state.language == Language::English);
    window.set_show_advanced(state.show_advanced);
    window.set_show_settings(state.show_settings);
    window.set_show_queue(state.show_queue);
    window.set_advanced_label(state.tr("Advanced tools panel", "고급 도구 패널").into());
    window.set_queue_panel_label(state.tr("Queue panel", "배치 큐 패널").into());
    window.set_advanced_label(state.tr("Tools", "도구").into());
    window.set_queue_panel_label(state.tr("Queue", "큐").into());
    window.set_running(state.busy());
    window.set_can_run(state.can_start());
    window.set_show_confirm_password(state.mode == Mode::Encrypt);
    window.set_has_keyfile(!state.keyfile_path.trim().is_empty());
    window.set_has_new_keyfile(!state.rotate_keyfile_path.trim().is_empty());
    window.set_has_input_file(state.has_input_file());
    window.set_drop_hovered(state.drop_hovered);
    window.set_queue_recursive(state.queue_recursive);
    window.set_queue_has_items(!state.queue_items.is_empty());
    window.set_can_queue_add(state.can_queue_add());
    window.set_can_queue_run(state.can_queue_run());
    window.set_can_queue_remove(state.can_queue_remove());
    window.set_can_queue_retry(state.can_queue_retry());
    window.set_can_stop_queue(state.queue_running);
    window.set_can_reopen_last_file(!state.recent_inputs.is_empty() && !state.busy());
    window.set_can_use_last_output_folder(state.last_output_folder.is_some() && state.has_input_file() && !state.busy());
    window.set_can_repeat_last_setup(state.last_success_mode.is_some() && !state.busy());
    window.set_can_open_result(state.last_completed_output.is_some() && !state.busy());
    window.set_can_copy_result(state.last_completed_output.is_some() && !state.busy());
    window.set_can_inspect(state.can_inspect());
    window.set_can_verify(state.can_verify());
    window.set_can_rotate(state.can_rotate());
    window.set_can_check_updates(state.can_check_updates());
    window.set_can_install_update(state.can_install_update());
    window.set_can_open_release(state.can_open_release_page());
    window.set_status_tone(state.status_tone.code());
    window.set_status_text(state.status_line.clone().into());
    window.set_status_detail(
        if state.queue_running {
            state.tr("The queue will stop after the current file if you press Stop queue.", "큐 중지를 누르면 현재 파일이 끝난 뒤 멈춥니다.")
        } else if matches!(state.status_tone, StatusTone::Success) {
            state.tr("Ready for another task.", "다음 작업을 바로 시작할 수 있습니다.")
        } else {
            state.readiness_hint()
        }
        .into(),
    );
    window.set_workspace_title(state.workspace_title().into());
    window.set_workspace_subtitle(state.workspace_subtitle().into());
    window.set_source_surface_title(state.source_surface_title().into());
    window.set_source_surface_subtitle(state.source_surface_subtitle().into());
    window.set_folder_input(state.input_kind == InputKind::Folder);
    window.set_input_kind_title(state.tr("Input kind", "입력 종류").into());
    window.set_input_kind_subtitle(
        state
            .tr(
                "Choose whether PillowLock should work with one file or package an entire folder into a single protected archive.",
                "파일 하나를 처리할지, 폴더 전체를 하나의 보호 아카이브로 묶을지 선택하세요.",
            )
            .into(),
    );
    window.set_file_input_label(state.input_kind_label(InputKind::File).into());
    window.set_folder_input_label(state.input_kind_label(InputKind::Folder).into());
    window.set_input_field_label(state.tr("1. Choose a file", "1. 파일 선택").into());
    window.set_input_path(state.input_path.clone().into());
    window.set_input_field_label(
        state
            .tr(
                if state.mode == Mode::Encrypt && state.input_kind == InputKind::Folder {
                    "1. Choose a folder"
                } else {
                    "1. Choose a file"
                },
                if state.mode == Mode::Encrypt && state.input_kind == InputKind::Folder {
                    "1. 폴더 선택"
                } else {
                    "1. 파일 선택"
                },
            )
            .into(),
    );
    window.set_browse_input_label(
        state
            .tr(
                if state.mode == Mode::Encrypt && state.input_kind == InputKind::Folder {
                    "Browse folders"
                } else {
                    "Browse files"
                },
                if state.mode == Mode::Encrypt && state.input_kind == InputKind::Folder {
                    "폴더 찾기"
                } else {
                    "파일 찾기"
                },
            )
            .into(),
    );
    window.set_browse_input_label(state.tr("Browse files", "파일 찾기").into());
    window.set_output_field_label(state.tr("Save result to", "저장 위치").into());
    window.set_output_placeholder(state.tr("Choose where the result should be saved", "결과 파일이 저장될 위치를 고르세요").into());
    window.set_output_path(state.output_path.clone().into());
    window.set_output_field_label(
        state
            .tr(
                if state.output_target_is_directory() {
                    "Restore folder to"
                } else {
                    "Save result to"
                },
                if state.output_target_is_directory() {
                    "폴더 복원 위치"
                } else {
                    "결과 저장 위치"
                },
            )
            .into(),
    );
    window.set_output_placeholder(
        state
            .tr(
                if state.output_target_is_directory() {
                    "Choose where the restored folder should be created"
                } else {
                    "Choose where the result should be saved"
                },
                if state.output_target_is_directory() {
                    "복원된 폴더를 만들 위치를 선택하세요"
                } else {
                    "결과를 저장할 위치를 선택하세요"
                },
            )
            .into(),
    );
    window.set_browse_output_label(
        state
            .tr(
                if state.output_target_is_directory() {
                    "Choose parent folder"
                } else {
                    "Choose location"
                },
                if state.output_target_is_directory() {
                    "상위 폴더 선택"
                } else {
                    "위치 선택"
                },
            )
            .into(),
    );
    window.set_compression_title(state.tr("Folder compression", "폴더 압축").into());
    window.set_compression_subtitle(
        state
            .tr(
                "Pick a preset for the temporary ZIP container or switch to advanced controls.",
                "임시 ZIP 컨테이너에 사용할 프리셋을 고르거나 고급 설정으로 전환하세요.",
            )
            .into(),
    );
    window.set_compression_fast_label(state.compression_preset_label(CompressionPreset::Fast).into());
    window.set_compression_balanced_label(state.compression_preset_label(CompressionPreset::Balanced).into());
    window.set_compression_maximum_label(state.compression_preset_label(CompressionPreset::Maximum).into());
    window.set_compression_none_label(state.compression_preset_label(CompressionPreset::None).into());
    window.set_compression_fast_selected(state.compression_preset == CompressionPreset::Fast);
    window.set_compression_balanced_selected(state.compression_preset == CompressionPreset::Balanced);
    window.set_compression_maximum_selected(state.compression_preset == CompressionPreset::Maximum);
    window.set_compression_none_selected(state.compression_preset == CompressionPreset::None);
    window.set_compression_advanced(state.compression_advanced);
    window.set_compression_advanced_label(state.tr("Advanced", "고급").into());
    window.set_compression_method_title(state.tr("Method", "방식").into());
    window.set_compression_store_label(state.tr("Store", "저장").into());
    window.set_compression_deflate_label(state.tr("Deflate", "Deflate").into());
    window.set_compression_method_deflate(state.compression_method == FolderCompressionMethod::Deflated);
    window.set_compression_level_title(state.tr("Level (0-9)", "레벨 (0-9)").into());
    window.set_compression_level(state.compression_level.to_string().into());
    window.set_compression_level_placeholder(state.tr("6", "6").into());
    window.set_suggest_output_label(state.tr("Use suggested path", "추천 경로").into());
    window.set_browse_output_label(state.tr("Choose location", "위치 선택").into());
    window.set_keyfile_title(state.tr("2. Optional key file", "2. 선택형 키 파일").into());
    window.set_keyfile_subtitle(state.tr("Optional extra key stored separately from the password.", "비밀번호와 분리해 보관하는 선택형 추가 키입니다.").into());
    window.set_keyfile_field_label(state.tr("Key file path", "키 파일 경로").into());
    window.set_keyfile_placeholder(state.tr("Optional. Keep it separate for extra protection.", "선택 사항입니다. 별도 보관하면 보안이 더 강해집니다.").into());
    window.set_keyfile_path(state.keyfile_path.clone().into());
    window.set_browse_keyfile_label(state.tr("Browse", "찾아보기").into());
    window.set_create_keyfile_label(state.tr("Create", "생성").into());
    window.set_clear_keyfile_label(state.tr("Clear", "지우기").into());
    window.set_password_title(state.tr("3. Password", "3. 비밀번호").into());
    window.set_password_subtitle(state.password_subtitle().into());
    window.set_password_field_label(state.tr("Password", "비밀번호").into());
    window.set_password_placeholder(state.tr("Password for this task", "이번 작업용 비밀번호").into());
    window.set_password(state.password_text().into());
    window.set_confirm_password_field_label(state.tr("Confirm password", "비밀번호 확인").into());
    window.set_confirm_password_placeholder(state.tr("Re-enter to avoid typos", "오타 방지를 위해 다시 입력하세요").into());
    window.set_confirm_password(state.confirm_password_text().into());
    window.set_input_field_label(state.tr("Choose a file", "파일 선택").into());
    window.set_keyfile_title(state.tr("Optional extra key", "선택형 추가 키").into());
    window.set_keyfile_subtitle(
        state
            .tr(
                "Skip this unless you want a second file-based secret stored separately from the password.",
                "비밀번호와 따로 보관할 두 번째 파일 기반 비밀키가 필요할 때만 사용하세요.",
            )
            .into(),
    );
    window.set_password_title(state.tr("Password", "비밀번호").into());
    window.set_recent_title(state.tr("Quick actions and recents", "빠른 작업과 최근 기록").into());
    window.set_recent_subtitle(state.tr("Keep momentum with the last file, output folder, and successful setup.", "마지막 파일, 출력 폴더, 성공 설정을 바로 다시 사용하세요.").into());
    window.set_recent_inputs_title(state.tr("Recent inputs", "최근 입력").into());
    window.set_recent_inputs_text(state.recent_inputs_text().into());
    window.set_recent_outputs_title(state.tr("Recent output folders", "최근 출력 폴더").into());
    window.set_recent_outputs_text(state.recent_outputs_text().into());
    window.set_recent_jobs_title(state.tr("Recent successful jobs", "최근 성공 작업").into());
    window.set_recent_jobs_text(state.recent_jobs_text().into());
    window.set_recent_title(state.tr("Quick actions and recents", "빠른 작업과 최근 기록").into());
    window.set_recent_subtitle(
        state
            .tr(
                "Jump back in with your last file, favorite output folder, or most recent successful setup.",
                "마지막 파일, 자주 쓰는 출력 폴더, 최근 성공 설정으로 바로 다시 시작하세요.",
            )
            .into(),
    );
    window.set_quick_repeat_label(state.tr("Reuse last setup", "마지막 설정 다시").into());
    window.set_quick_reopen_label(state.tr("Reopen last file", "최근 파일 다시 열기").into());
    window.set_quick_output_folder_label(state.tr("Use last output folder", "최근 출력 폴더 사용").into());
    window.set_action_title(state.tr("4. Run", "4. 실행").into());
    window.set_action_subtitle(state.tr("Run the task once everything looks right.", "입력 내용을 확인한 뒤 바로 실행하세요.").into());
    window.set_action_label(state.action_label().into());
    window.set_action_caption(state.action_caption().into());
    window.set_action_title(state.tr("Run task", "작업 실행").into());
    window.set_action_subtitle(
        state
            .tr(
                "When the file path and password look right, run the task.",
                "파일 경로와 비밀번호를 확인한 뒤 작업을 실행하세요.",
            )
            .into(),
    );
    window.set_reset_label(state.tr("Reset fields", "입력 초기화").into());
    window.set_open_result_label(state.tr("Open output folder", "출력 폴더 열기").into());
    window.set_copy_result_label(state.tr("Copy result path", "결과 경로 복사").into());
    window.set_queue_current_label(state.tr("Add current to queue", "현재 설정 큐 추가").into());
    window.set_queue_title(state.tr("Batch queue", "배치 큐").into());
    window.set_queue_subtitle(state.tr("Queue up files and run them sequentially with the same current password.", "현재 비밀번호로 여러 파일을 순차 처리할 수 있습니다.").into());
    window.set_queue_summary(state.queue_summary().into());
    window.set_queue_empty_text(state.tr("The queue is empty. Add the current file, browse multiple files, or scan a folder.", "큐가 비어 있습니다. 현재 파일을 추가하거나 여러 파일, 폴더를 큐에 넣어보세요.").into());
    window.set_queue_items(string_model(state.queue_display_rows()));
    window.set_selected_queue_index(state.selected_queue_index());
    window.set_add_current_queue_label(state.tr("Add current", "현재 추가").into());
    window.set_add_folder_label(state.tr("Add folder", "폴더 추가").into());
    window.set_remove_selected_queue_label(state.tr("Remove selected", "선택 제거").into());
    window.set_run_queue_label(state.tr("Run queue", "큐 실행").into());
    window.set_stop_queue_label(state.tr("Stop queue", "큐 중지").into());
    window.set_retry_failed_queue_label(state.tr("Retry failed", "실패 재시도").into());
    window.set_clear_finished_queue_label(state.tr("Clear finished", "완료 정리").into());
    window.set_advanced_title(state.tr("Advanced details", "고급 정보").into());
    window.set_advanced_subtitle(state.tr("Inspect the protected file, verify integrity, or rotate keys without changing the payload.", "보호 파일 검사, 무결성 검증, 키 교체를 한 화면에서 처리할 수 있습니다.").into());
    window.set_selection_card_title(state.tr("Selection", "선택 정보").into());
    window.set_security_card_title(state.tr("Security", "보안 정보").into());
    window.set_activity_card_title(state.tr("Recent activity", "최근 활동").into());
    window.set_tool_card_title(state.tr("Advanced tools", "고급 도구").into());
    window.set_selection_details(state.selection_details().into());
    window.set_security_details(state.security_details().into());
    window.set_activity_details(state.activity_details().into());
    window.set_inspect_label(state.tr("Inspect", "검사").into());
    window.set_verify_label(state.tr("Verify", "검증").into());
    window.set_rotate_label(state.tr("Rotate keys", "키 교체").into());
    window.set_advanced_output_title(state.tr("Tool output", "도구 출력").into());
    window.set_advanced_tool_output(state.advanced_tool_output.clone().into());
    window.set_rotate_password_label(state.tr("New password", "새 비밀번호").into());
    window.set_rotate_password_placeholder(state.tr("Password for the updated protected file", "새 보호 파일용 비밀번호").into());
    window.set_rotate_password(state.rotate_password_text().into());
    window.set_rotate_confirm_label(state.tr("Confirm new password", "새 비밀번호 확인").into());
    window.set_rotate_confirm_placeholder(state.tr("Re-enter the new password", "새 비밀번호를 다시 입력하세요").into());
    window.set_rotate_confirm_password(state.rotate_confirm_password_text().into());
    window.set_rotate_keyfile_label(state.tr("New key file (optional)", "새 키 파일 (선택)").into());
    window.set_rotate_keyfile_placeholder(state.tr("Optional replacement key file path", "새로 사용할 키 파일 경로").into());
    window.set_rotate_keyfile_path(state.rotate_keyfile_path.clone().into());
    window.set_browse_new_keyfile_label(state.tr("Browse new key file", "새 키 파일 선택").into());
    window.set_clear_new_keyfile_label(state.tr("Clear new key file", "새 키 파일 지우기").into());
    window.set_settings_button_label(state.tr("Settings", "설정").into());
    window.set_settings_title(state.tr("Settings", "설정").into());
    window.set_settings_subtitle(
        state
            .tr(
                "Keep app preferences and update controls here so the main workspace stays focused on the file task.",
                "메인 작업 화면은 파일 처리에만 집중하고 앱 환경과 업데이트 관리는 여기에서 다룹니다.",
            )
            .into(),
    );
    window.set_settings_close_label(state.tr("Close", "닫기").into());
    window.set_settings_language_title(state.tr("Language", "언어").into());
    window.set_settings_language_subtitle(
        state
            .tr(
                "Choose the language used across PillowLock.",
                "PillowLock 전체에 사용할 언어를 고릅니다.",
            )
            .into(),
    );
    window.set_settings_panels_title(state.tr("Workspace panels", "작업 패널").into());
    window.set_settings_panels_subtitle(
        state
            .tr(
                "Keep the batch queue visible only when you need it.",
                "배치 큐가 필요할 때만 작업 화면에 보이게 합니다.",
            )
            .into(),
    );
    window.set_update_card_title(state.tr("Release updates", "릴리스 업데이트").into());
    window.set_update_card_subtitle(
        state
            .tr(
                "Check GitHub Releases, open the latest release page, or download and launch the newest installer.",
                "GitHub Releases를 확인하고 최신 릴리스 페이지를 열거나 최신 설치 파일을 내려받아 실행할 수 있습니다.",
            )
            .into(),
    );
    window.set_current_version_title(state.tr("Current version", "현재 버전").into());
    window.set_current_version_text(format!("v{}", state.update_ui.current_version).into());
    window.set_advanced_label(state.tr("File tools", "보호 파일 도구").into());
    window.set_mode_group_title(state.tr("What do you want to do?", "무엇을 하시겠어요?").into());
    window.set_mode_group_subtitle(
        state
            .tr(
                "Choose whether this file should be protected or whether an existing protected file should be restored.",
                "파일을 새로 보호할지, 기존 보호 파일을 복원할지 먼저 선택하세요.",
            )
            .into(),
    );
    window.set_mode_group_hint(state.mode_group_hint().into());
    window.set_profile_group_title(state.tr("How strong should protection be?", "보호 강도를 골라주세요").into());
    window.set_profile_group_subtitle(
        state
            .tr(
                "Balanced is the simpler default. Hardened uses more memory for tougher password defense.",
                "균형은 기본 선택에 적합하고, 강화는 더 강한 비밀번호 방어를 위해 메모리를 더 사용합니다.",
            )
            .into(),
    );
    window.set_profile_group_hint(state.profile_group_hint().into());
    window.set_input_field_label(
        state
            .tr(
                if state.mode == Mode::Encrypt && state.input_kind == InputKind::Folder {
                    "Choose your folder"
                } else {
                    "Choose your file"
                },
                if state.mode == Mode::Encrypt && state.input_kind == InputKind::Folder {
                    "폴더를 선택하세요"
                } else {
                    "파일을 선택하세요"
                },
            )
            .into(),
    );
    window.set_browse_input_label(
        state
            .tr(
                if state.mode == Mode::Encrypt && state.input_kind == InputKind::Folder {
                    "Browse folders"
                } else {
                    "Browse files"
                },
                if state.mode == Mode::Encrypt && state.input_kind == InputKind::Folder {
                    "폴더 찾기"
                } else {
                    "파일 찾기"
                },
            )
            .into(),
    );
    window.set_output_field_label(
        state
            .tr(
                if state.output_target_is_directory() {
                    "Restore folder to"
                } else {
                    "Save result to"
                },
                if state.output_target_is_directory() {
                    "폴더 복원 위치"
                } else {
                    "결과 저장 위치"
                },
            )
            .into(),
    );
    window.set_output_placeholder(
        state
            .tr(
                if state.output_target_is_directory() {
                    "Choose where the restored folder should be created"
                } else {
                    "Choose where the result should be saved"
                },
                if state.output_target_is_directory() {
                    "복원된 폴더를 만들 위치를 선택하세요"
                } else {
                    "결과를 저장할 위치를 선택하세요"
                },
            )
            .into(),
    );
    window.set_browse_output_label(
        state
            .tr(
                if state.output_target_is_directory() {
                    "Choose parent folder"
                } else {
                    "Choose location"
                },
                if state.output_target_is_directory() {
                    "상위 폴더 선택"
                } else {
                    "위치 선택"
                },
            )
            .into(),
    );
    window.set_input_field_label(state.tr("Choose your file", "파일을 선택하세요").into());
    window.set_keyfile_title(state.tr("Optional extra key", "선택형 추가 키").into());
    window.set_keyfile_subtitle(
        state
            .tr(
                "Most people can skip this. Use it only when you want a second secret file stored separately from the password.",
                "대부분은 이 단계를 건너뛰어도 됩니다. 비밀번호와 별도로 보관할 두 번째 비밀 파일이 필요할 때만 사용하세요.",
            )
            .into(),
    );
    window.set_password_title(state.tr("Set the password", "비밀번호를 입력하세요").into());
    window.set_recent_title(state.tr("Quick restart", "빠른 다시 시작").into());
    window.set_recent_subtitle(
        state
            .tr(
                "Jump back in with the last file, save folder, or successful setup without filling everything again.",
                "마지막 파일, 저장 폴더, 성공한 설정을 다시 불러와 한 번에 이어서 작업하세요.",
            )
            .into(),
    );
    window.set_action_title(state.tr("Ready to run", "실행 준비").into());
    window.set_action_subtitle(
        state
            .tr(
                "Check the file path and password, then use the main blue button to finish this task.",
                "파일 경로와 비밀번호를 확인한 뒤, 파란색 메인 버튼으로 작업을 마무리하세요.",
            )
            .into(),
    );
    window.set_queue_empty_text(
        state
            .tr(
                "The queue is empty. Add the current file, drop several files, or scan a folder when you want batch work.",
                "큐가 비어 있습니다. 여러 파일을 한꺼번에 처리하려면 현재 파일을 추가하거나 여러 파일 또는 폴더를 넣어보세요.",
            )
            .into(),
    );
    window.set_tools_title(state.tr("File tools", "보호 파일 도구").into());
    window.set_tools_subtitle(
        state
            .tr(
                "Inspect a protected-file header, verify integrity, or rotate keys without changing the encrypted payload.",
                "보호 파일 헤더 확인, 무결성 검증, 키 교체를 암호문 본문을 바꾸지 않고 처리할 수 있습니다.",
            )
            .into(),
    );
    window.set_tools_close_label(state.tr("Close", "닫기").into());
    window.set_tool_card_title(state.tr("Choose a file tool", "보호 파일 도구를 선택하세요").into());
    window.set_advanced_subtitle(
        state
            .tr(
                "Inspect shows the safe header summary. Verify checks the whole protected file. Rotate keys rewrites only the protected key wrapper.",
                "검사는 안전한 헤더 요약을 보여주고, 검증은 전체 보호 파일을 확인하며, 키 교체는 보호된 키 래퍼만 다시 작성합니다.",
            )
            .into(),
    );
    window.set_update_status_title(state.tr("Update status", "업데이트 상태").into());
    window.set_update_status_text(state.update_ui.status_line.clone().into());
    window.set_update_details_title(state.tr("Details", "세부 정보").into());
    window.set_update_details_text(state.update_ui.details.clone().into());
    window.set_check_updates_label(state.tr("Check for updates", "업데이트 확인").into());
    window.set_install_update_label(state.tr("Download and install", "다운로드 후 설치").into());
    window.set_open_release_label(state.tr("Open release page", "릴리스 페이지 열기").into());
    window.set_input_field_label(
        state
            .tr(
                if state.mode == Mode::Encrypt && state.input_kind == InputKind::Folder {
                    "Choose your folder"
                } else {
                    "Choose your file"
                },
                if state.mode == Mode::Encrypt && state.input_kind == InputKind::Folder {
                    "폴더를 선택하세요"
                } else {
                    "파일을 선택하세요"
                },
            )
            .into(),
    );
    window.set_browse_input_label(
        state
            .tr(
                if state.mode == Mode::Encrypt && state.input_kind == InputKind::Folder {
                    "Browse folders"
                } else {
                    "Browse files"
                },
                if state.mode == Mode::Encrypt && state.input_kind == InputKind::Folder {
                    "폴더 찾기"
                } else {
                    "파일 찾기"
                },
            )
            .into(),
    );
    window.set_output_field_label(
        state
            .tr(
                if state.output_target_is_directory() {
                    "Restore folder to"
                } else {
                    "Save result to"
                },
                if state.output_target_is_directory() {
                    "폴더 복원 위치"
                } else {
                    "결과 저장 위치"
                },
            )
            .into(),
    );
    window.set_output_placeholder(
        state
            .tr(
                if state.output_target_is_directory() {
                    "Choose where the restored folder should be created"
                } else {
                    "Choose where the result should be saved"
                },
                if state.output_target_is_directory() {
                    "복원된 폴더를 만들 위치를 선택하세요"
                } else {
                    "결과를 저장할 위치를 선택하세요"
                },
            )
            .into(),
    );
    window.set_browse_output_label(
        state
            .tr(
                if state.output_target_is_directory() {
                    "Choose parent folder"
                } else {
                    "Choose location"
                },
                if state.output_target_is_directory() {
                    "상위 폴더 선택"
                } else {
                    "위치 선택"
                },
            )
            .into(),
    );
}

fn start_update_check(weak: &slint::Weak<AppWindow>, shared: &Arc<Mutex<AppState>>) {
    let Some(window) = weak.upgrade() else {
        return;
    };
    let request = {
        let mut state = shared.lock().expect("app state poisoned");
        match state.prepare_update_check() {
            Ok(request) => {
                sync_ui(&window, &state);
                let _ = state.save_settings();
                request
            }
            Err(_) => {
                sync_ui(&window, &state);
                let _ = state.save_settings();
                return;
            }
        }
    };
    let weak = weak.clone();
    let shared = shared.clone();
    thread::spawn(move || {
        let result = fetch_latest_release_info(&request.repo_slug);
        let _ = slint::invoke_from_event_loop(move || {
            if let Some(window) = weak.upgrade() {
                let mut state = shared.lock().expect("app state poisoned");
                state.complete_update_check(result);
                sync_ui(&window, &state);
                let _ = state.save_settings();
            }
        });
    });
}

fn start_update_install(weak: &slint::Weak<AppWindow>, shared: &Arc<Mutex<AppState>>) {
    let Some(window) = weak.upgrade() else {
        return;
    };
    let request = {
        let mut state = shared.lock().expect("app state poisoned");
        match state.prepare_update_install() {
            Ok(request) => {
                sync_ui(&window, &state);
                let _ = state.save_settings();
                request
            }
            Err(_) => {
                sync_ui(&window, &state);
                let _ = state.save_settings();
                return;
            }
        }
    };
    let weak = weak.clone();
    let shared = shared.clone();
    thread::spawn(move || {
        let result = download_and_launch_installer(&request.download_url, &request.asset_name);
        let _ = slint::invoke_from_event_loop(move || {
            if let Some(window) = weak.upgrade() {
                let mut state = shared.lock().expect("app state poisoned");
                state.complete_update_install(result);
                sync_ui(&window, &state);
                let _ = state.save_settings();
            }
        });
    });
}

fn with_state<F>(weak: &slint::Weak<AppWindow>, shared: &Arc<Mutex<AppState>>, action: F)
where
    F: FnOnce(&AppWindow, &mut AppState),
{
    if let Some(window) = weak.upgrade() {
        let mut state = shared.lock().expect("app state poisoned");
        action(&window, &mut state);
        sync_ui(&window, &state);
        let _ = state.save_settings();
    }
}

fn install_callbacks(window: &AppWindow, shared: Arc<Mutex<AppState>>) {
    let weak = window.as_weak();

    window.window().on_winit_window_event({
        let weak = weak.clone();
        let shared = shared.clone();
        move |_slint_window, event| {
            match event {
                winit::event::WindowEvent::HoveredFile(_) => {
                    with_state(&weak, &shared, |_window, state| {
                        if !state.busy() {
                            state.drop_hovered = true;
                        }
                    });
                }
                winit::event::WindowEvent::HoveredFileCancelled => {
                    with_state(&weak, &shared, |_window, state| {
                        state.drop_hovered = false;
                    });
                }
                winit::event::WindowEvent::DroppedFile(path) => {
                    let path = path.clone();
                    with_state(&weak, &shared, |_window, state| {
                        if !state.busy() {
                            state.handle_dropped_file(path);
                        } else {
                            state.drop_hovered = false;
                        }
                    });
                }
                _ => {}
            }
            EventResult::Propagate
        }
    });

    window.on_form_edited({
        let weak = weak.clone();
        let shared = shared.clone();
        move || with_state(&weak, &shared, |window, state| {
            pull_form_fields(window, state);
            if !state.busy() {
                state.set_status(StatusTone::Idle, state.default_status());
            }
        })
    });
    window.on_browse_input({
        let weak = weak.clone();
        let shared = shared.clone();
        move || with_state(&weak, &shared, |window, state| {
            pull_form_fields(window, state);
            state.browse_input();
        })
    });
    window.on_browse_output({
        let weak = weak.clone();
        let shared = shared.clone();
        move || with_state(&weak, &shared, |window, state| {
            pull_form_fields(window, state);
            state.browse_output();
        })
    });
    window.on_suggest_output({
        let weak = weak.clone();
        let shared = shared.clone();
        move || with_state(&weak, &shared, |window, state| {
            pull_form_fields(window, state);
            state.refresh_output_suggestion();
            state.set_status(StatusTone::Idle, state.default_status());
        })
    });
    window.on_browse_keyfile({
        let weak = weak.clone();
        let shared = shared.clone();
        move || with_state(&weak, &shared, |window, state| {
            pull_form_fields(window, state);
            state.browse_keyfile();
        })
    });
    window.on_create_keyfile({
        let weak = weak.clone();
        let shared = shared.clone();
        move || with_state(&weak, &shared, |window, state| {
            pull_form_fields(window, state);
            state.generate_keyfile_file();
        })
    });
    window.on_clear_keyfile({
        let weak = weak.clone();
        let shared = shared.clone();
        move || with_state(&weak, &shared, |window, state| {
            pull_form_fields(window, state);
            state.keyfile_path.clear();
            state.set_status(StatusTone::Idle, state.default_status());
        })
    });
    window.on_browse_new_keyfile({
        let weak = weak.clone();
        let shared = shared.clone();
        move || with_state(&weak, &shared, |window, state| {
            pull_form_fields(window, state);
            state.browse_new_keyfile();
        })
    });
    window.on_clear_new_keyfile({
        let weak = weak.clone();
        let shared = shared.clone();
        move || with_state(&weak, &shared, |window, state| {
            pull_form_fields(window, state);
            state.rotate_keyfile_path.clear();
            state.set_status(StatusTone::Idle, state.default_status());
        })
    });
    window.on_clear_form({
        let weak = weak.clone();
        let shared = shared.clone();
        move || with_state(&weak, &shared, |_window, state| state.clear_form())
    });
    window.on_select_mode_encrypt({
        let weak = weak.clone();
        let shared = shared.clone();
        move || with_state(&weak, &shared, |_window, state| state.set_mode(Mode::Encrypt))
    });
    window.on_select_mode_decrypt({
        let weak = weak.clone();
        let shared = shared.clone();
        move || with_state(&weak, &shared, |_window, state| state.set_mode(Mode::Decrypt))
    });
    window.on_select_profile_balanced({
        let weak = weak.clone();
        let shared = shared.clone();
        move || with_state(&weak, &shared, |_window, state| state.set_profile(SecurityProfile::Balanced))
    });
    window.on_select_profile_hardened({
        let weak = weak.clone();
        let shared = shared.clone();
        move || with_state(&weak, &shared, |_window, state| state.set_profile(SecurityProfile::Hardened))
    });
    window.on_select_language_english({
        let weak = weak.clone();
        let shared = shared.clone();
        move || with_state(&weak, &shared, |_window, state| state.set_language(Language::English))
    });
    window.on_select_language_korean({
        let weak = weak.clone();
        let shared = shared.clone();
        move || with_state(&weak, &shared, |_window, state| state.set_language(Language::Korean))
    });
    window.on_select_input_file({
        let weak = weak.clone();
        let shared = shared.clone();
        move || with_state(&weak, &shared, |_window, state| state.set_input_kind(InputKind::File))
    });
    window.on_select_input_folder({
        let weak = weak.clone();
        let shared = shared.clone();
        move || with_state(&weak, &shared, |_window, state| state.set_input_kind(InputKind::Folder))
    });
    window.on_select_compression_fast({
        let weak = weak.clone();
        let shared = shared.clone();
        move || with_state(&weak, &shared, |_window, state| state.set_compression_preset(CompressionPreset::Fast))
    });
    window.on_select_compression_balanced({
        let weak = weak.clone();
        let shared = shared.clone();
        move || with_state(&weak, &shared, |_window, state| state.set_compression_preset(CompressionPreset::Balanced))
    });
    window.on_select_compression_maximum({
        let weak = weak.clone();
        let shared = shared.clone();
        move || with_state(&weak, &shared, |_window, state| state.set_compression_preset(CompressionPreset::Maximum))
    });
    window.on_select_compression_none({
        let weak = weak.clone();
        let shared = shared.clone();
        move || with_state(&weak, &shared, |_window, state| state.set_compression_preset(CompressionPreset::None))
    });
    window.on_toggle_compression_advanced({
        let weak = weak.clone();
        let shared = shared.clone();
        move || with_state(&weak, &shared, |_window, state| state.toggle_compression_advanced())
    });
    window.on_select_compression_method_stored({
        let weak = weak.clone();
        let shared = shared.clone();
        move || with_state(&weak, &shared, |_window, state| state.set_compression_method(FolderCompressionMethod::Stored))
    });
    window.on_select_compression_method_deflated({
        let weak = weak.clone();
        let shared = shared.clone();
        move || with_state(&weak, &shared, |_window, state| state.set_compression_method(FolderCompressionMethod::Deflated))
    });
    window.on_toggle_advanced({
        let weak = weak.clone();
        let shared = shared.clone();
        move || with_state(&weak, &shared, |_window, state| state.show_advanced = !state.show_advanced)
    });
    window.on_toggle_settings({
        let weak = weak.clone();
        let shared = shared.clone();
        move || with_state(&weak, &shared, |_window, state| state.show_settings = !state.show_settings)
    });
    window.on_toggle_queue({
        let weak = weak.clone();
        let shared = shared.clone();
        move || with_state(&weak, &shared, |_window, state| state.show_queue = !state.show_queue)
    });
    window.on_toggle_queue_recursive({
        let weak = weak.clone();
        let shared = shared.clone();
        move || with_state(&weak, &shared, |_window, state| state.queue_recursive = !state.queue_recursive)
    });
    window.on_queue_current({
        let weak = weak.clone();
        let shared = shared.clone();
        move || with_state(&weak, &shared, |window, state| {
            pull_form_fields(window, state);
            match state.enqueue_current_form() {
                Ok(()) => state.set_status(StatusTone::Success, state.tr("Current task added to the queue.", "현재 작업을 큐에 추가했습니다.")),
                Err(message) => state.set_status(StatusTone::Error, message),
            }
        })
    });
    window.on_add_folder({
        let weak = weak.clone();
        let shared = shared.clone();
        move || with_state(&weak, &shared, |window, state| {
            pull_form_fields(window, state);
            state.add_folder_to_queue();
        })
    });
    window.on_remove_queue_item({
        let weak = weak.clone();
        let shared = shared.clone();
        move || with_state(&weak, &shared, |_window, state| state.remove_selected_queue_item())
    });
    window.on_retry_failed_jobs({
        let weak = weak.clone();
        let shared = shared.clone();
        move || with_state(&weak, &shared, |_window, state| state.retry_failed_jobs())
    });
    window.on_clear_finished_queue({
        let weak = weak.clone();
        let shared = shared.clone();
        move || with_state(&weak, &shared, |_window, state| state.clear_finished_queue_items())
    });
    window.on_select_queue_item({
        let weak = weak.clone();
        let shared = shared.clone();
        move |index| with_state(&weak, &shared, |_window, state| state.select_queue_index(index))
    });
    window.on_quick_reopen_last_file({
        let weak = weak.clone();
        let shared = shared.clone();
        move || with_state(&weak, &shared, |_window, state| state.quick_reopen_last_file())
    });
    window.on_quick_use_last_output_folder({
        let weak = weak.clone();
        let shared = shared.clone();
        move || with_state(&weak, &shared, |_window, state| state.quick_use_last_output_folder())
    });
    window.on_quick_repeat_last_setup({
        let weak = weak.clone();
        let shared = shared.clone();
        move || with_state(&weak, &shared, |_window, state| state.quick_repeat_last_setup())
    });
    window.on_open_output_folder({
        let weak = weak.clone();
        let shared = shared.clone();
        move || with_state(&weak, &shared, |_window, state| state.open_last_output_folder())
    });
    window.on_copy_output_path({
        let weak = weak.clone();
        let shared = shared.clone();
        move || with_state(&weak, &shared, |_window, state| state.copy_last_output_path())
    });
    window.on_check_for_updates({
        let weak = weak.clone();
        let shared = shared.clone();
        move || start_update_check(&weak, &shared)
    });
    window.on_install_update({
        let weak = weak.clone();
        let shared = shared.clone();
        move || start_update_install(&weak, &shared)
    });
    window.on_open_release_page({
        let weak = weak.clone();
        let shared = shared.clone();
        move || with_state(&weak, &shared, |_window, state| state.open_release_page())
    });
    window.on_inspect_vault({
        let weak = weak.clone();
        let shared = shared.clone();
        move || with_state(&weak, &shared, |window, state| {
            pull_form_fields(window, state);
            state.inspect_current_vault();
        })
    });
    window.on_cancel_queue({
        let weak = weak.clone();
        let shared = shared.clone();
        move || with_state(&weak, &shared, |_window, state| state.request_queue_cancel())
    });
    window.on_verify_vault({
        let weak = weak.clone();
        let shared = shared.clone();
        move || {
            let Some(window) = weak.upgrade() else { return; };
            let request = {
                let mut state = shared.lock().expect("app state poisoned");
                pull_form_fields(&window, &mut state);
                match state.prepare_verify() {
                    Ok(request) => {
                        sync_ui(&window, &state);
                        let _ = state.save_settings();
                        request
                    }
                    Err(_) => {
                        sync_ui(&window, &state);
                        let _ = state.save_settings();
                        return;
                    }
                }
            };
            let weak = weak.clone();
            let shared = shared.clone();
            thread::spawn(move || {
                let VerifyRequest { input, keyfile, language, password } = request;
                let result = verify_vault(&input, password.expose_secret(), keyfile.as_deref())
                    .map_err(|error| error_to_text(&error, language));
                let _ = slint::invoke_from_event_loop(move || {
                    if let Some(window) = weak.upgrade() {
                        let mut state = shared.lock().expect("app state poisoned");
                        state.complete_verify(result);
                        sync_ui(&window, &state);
                        let _ = state.save_settings();
                    }
                });
            });
        }
    });
    window.on_rotate_keys({
        let weak = weak.clone();
        let shared = shared.clone();
        move || {
            let Some(window) = weak.upgrade() else { return; };
            let request = {
                let mut state = shared.lock().expect("app state poisoned");
                pull_form_fields(&window, &mut state);
                match state.prepare_rotate() {
                    Ok(request) => {
                        sync_ui(&window, &state);
                        let _ = state.save_settings();
                        request
                    }
                    Err(_) => {
                        sync_ui(&window, &state);
                        let _ = state.save_settings();
                        return;
                    }
                }
            };
            let weak = weak.clone();
            let shared = shared.clone();
            thread::spawn(move || {
                let RotateRequest { input, output, old_keyfile, new_keyfile, language, old_password, new_password } = request;
                let result = rewrap_vault(
                    &input,
                    &output,
                    old_password.expose_secret(),
                    old_keyfile.as_deref(),
                    new_password.expose_secret(),
                    new_keyfile.as_deref(),
                )
                .map(|_| output)
                .map_err(|error| error_to_text(&error, language));
                let _ = slint::invoke_from_event_loop(move || {
                    if let Some(window) = weak.upgrade() {
                        let mut state = shared.lock().expect("app state poisoned");
                        state.complete_rotate(result);
                        sync_ui(&window, &state);
                        let _ = state.save_settings();
                    }
                });
            });
        }
    });
    window.on_run_queue({
        let weak = weak.clone();
        let shared = shared.clone();
        move || {
            let Some(window) = weak.upgrade() else { return; };
            let request = {
                let mut state = shared.lock().expect("app state poisoned");
                pull_form_fields(&window, &mut state);
                match state.prepare_queue_run() {
                    Ok(request) => {
                        sync_ui(&window, &state);
                        let _ = state.save_settings();
                        request
                    }
                    Err(_) => {
                        sync_ui(&window, &state);
                        let _ = state.save_settings();
                        return;
                    }
                }
            };
            let weak = weak.clone();
            let shared = shared.clone();
            thread::spawn(move || {
                for item in request.items {
                    let id = item.id;
                    let weak_start = weak.clone();
                    let shared_start = shared.clone();
                    let _ = slint::invoke_from_event_loop(move || {
                        if let Some(window) = weak_start.upgrade() {
                            let mut state = shared_start.lock().expect("app state poisoned");
                            state.mark_queue_item_running(id);
                            sync_ui(&window, &state);
                            let _ = state.save_settings();
                        }
                    });
                    let keyfile = item.keyfile_path_session.as_ref().map(PathBuf::from);
                    let input = PathBuf::from(&item.input_path);
                    let output = PathBuf::from(&item.output_path);
                    let result = match item.mode {
                        Mode::Encrypt => encrypt_file_with_cancel(
                            &input,
                            &output,
                            request.password.expose_secret(),
                            &EncryptOptions {
                                config: item.profile.config(),
                                keyfile,
                                folder_archive: item
                                    .folder_compression
                                    .map(|compression| FolderArchiveOptions { compression }),
                            },
                            request.cancel_flag.as_ref(),
                        )
                        .map(|_| output.clone()),
                        Mode::Decrypt => decrypt_file_with_cancel(
                            &input,
                            &output,
                            request.password.expose_secret(),
                            &DecryptOptions { keyfile },
                            request.cancel_flag.as_ref(),
                        )
                        .map(|_| output.clone()),
                    };
                    let weak_finish = weak.clone();
                    let shared_finish = shared.clone();
                    let language = request.language;
                    let stop_now = matches!(result, Err(VaultError::Cancelled));
                    let _ = slint::invoke_from_event_loop(move || {
                        if let Some(window) = weak_finish.upgrade() {
                            let mut state = shared_finish.lock().expect("app state poisoned");
                            state.finish_queue_item(id, result, language);
                            sync_ui(&window, &state);
                            let _ = state.save_settings();
                        }
                    });
                    if stop_now || request.cancel_flag.load(Ordering::Relaxed) {
                        break;
                    }
                }
                let weak_done = weak.clone();
                let shared_done = shared.clone();
                let _ = slint::invoke_from_event_loop(move || {
                    if let Some(window) = weak_done.upgrade() {
                        let mut state = shared_done.lock().expect("app state poisoned");
                        state.finish_queue_run();
                        sync_ui(&window, &state);
                        let _ = state.save_settings();
                    }
                });
            });
        }
    });
    window.on_run_job({
        let weak = weak.clone();
        let shared = shared.clone();
        move || {
            let Some(window) = weak.upgrade() else { return; };
            let job = {
                let mut state = shared.lock().expect("app state poisoned");
                pull_form_fields(&window, &mut state);
                match state.prepare_job() {
                    Ok(job) => {
                        sync_ui(&window, &state);
                        let _ = state.save_settings();
                        job
                    }
                    Err(_) => {
                        sync_ui(&window, &state);
                        let _ = state.save_settings();
                        return;
                    }
                }
            };
            let weak = weak.clone();
            let shared = shared.clone();
            thread::spawn(move || {
                let JobRequest {
                    input,
                    output,
                    keyfile,
                    input_kind,
                    folder_compression,
                    language,
                    mode,
                    profile,
                    password,
                    ..
                } = job;
                let input_for_ui = input.clone();
                let result = match mode {
                    Mode::Encrypt => encrypt_file(
                        &input,
                        &output,
                        password.expose_secret(),
                        &EncryptOptions {
                            config: profile.config(),
                            keyfile,
                            folder_archive: if input_kind == InputKind::Folder {
                                folder_compression.map(|compression| FolderArchiveOptions { compression })
                            } else {
                                None
                            },
                        },
                    )
                    .map(|_| output.clone()),
                    Mode::Decrypt => decrypt_file(
                        &input,
                        &output,
                        password.expose_secret(),
                        &DecryptOptions { keyfile },
                    )
                    .map(|_| output.clone()),
                }
                .map_err(|error| error_to_text(&error, language));
                let _ = slint::invoke_from_event_loop(move || {
                    if let Some(window) = weak.upgrade() {
                        let mut state = shared.lock().expect("app state poisoned");
                        state.complete_job(mode, input_for_ui, profile, result);
                        sync_ui(&window, &state);
                        let _ = state.save_settings();
                    }
                });
            });
        }
    });
}

fn main() -> Result<(), slint::PlatformError> {
    let _backend = slint::BackendSelector::new()
        .backend_name("winit".into())
        .select()?;
    let window = AppWindow::new()?;
    let mut initial_state = load_settings();
    if let Ok(removed) = cleanup_stale_tempfiles() {
        if removed > 0 {
            initial_state.add_log(format!("Recovered {removed} stale temporary file(s)."));
        }
    }
    if let Some(path) = env::args_os().nth(1).map(PathBuf::from) {
        initial_state.apply_input_path(path);
    }
    let shared = Arc::new(Mutex::new(initial_state));
    install_callbacks(&window, shared.clone());
    {
        let state = shared.lock().expect("app state poisoned");
        sync_ui(&window, &state);
    }
    {
        let state = shared.lock().expect("app state poisoned");
        if state.update_ui.repo_slug.is_some() {
            drop(state);
            start_update_check(&window.as_weak(), &shared);
        }
    }
    window.run()
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn recent_lists_are_trimmed_and_pruned() {
        let dir = tempdir().unwrap();
        let mut state = AppState::default();
        for index in 0..12 {
            let input = dir.path().join(format!("input-{index}.txt"));
            fs::write(&input, b"data").unwrap();
            let output_dir = dir.path().join(format!("out-{index}"));
            fs::create_dir_all(&output_dir).unwrap();
            let output = output_dir.join("result.plock");
            state.record_success(Mode::Encrypt, SecurityProfile::Balanced, &input, &output);
        }
        assert_eq!(state.recent_inputs.len(), MAX_RECENT_ITEMS);
        assert_eq!(state.recent_output_folders.len(), MAX_RECENT_ITEMS);
        assert_eq!(state.recent_successes.len(), MAX_RECENT_ITEMS);
        let newest = PathBuf::from(&state.recent_inputs[0]);
        fs::remove_file(newest).unwrap();
        state.prune_recent_entries();
        assert_eq!(state.recent_inputs.len(), MAX_RECENT_ITEMS - 1);
    }

    #[test]
    fn second_drop_is_queued_after_primary_input() {
        let mut state = AppState::default();
        state.handle_dropped_file(PathBuf::from("first.txt"));
        state.handle_dropped_file(PathBuf::from("second.txt"));
        assert_eq!(state.input_path, "first.txt");
        assert_eq!(state.queue_items.len(), 1);
        assert_eq!(state.queue_items[0].input_path, "second.txt");
    }

    #[test]
    fn retry_failed_jobs_only_resets_failed_items() {
        let mut state = AppState::default();
        state.queue_items = vec![
            QueuedJob { id: 1, mode: Mode::Encrypt, input_kind: InputKind::File, payload_kind: PayloadKind::SingleFile, input_path: "a".into(), output_path: "b".into(), keyfile_path_session: None, folder_compression: None, profile: SecurityProfile::Balanced, status: QueueStatus::Failed, progress: 0, last_error: Some("boom".into()) },
            QueuedJob { id: 2, mode: Mode::Encrypt, input_kind: InputKind::File, payload_kind: PayloadKind::SingleFile, input_path: "c".into(), output_path: "d".into(), keyfile_path_session: None, folder_compression: None, profile: SecurityProfile::Balanced, status: QueueStatus::Cancelled, progress: 0, last_error: Some("cancelled".into()) },
        ];
        state.retry_failed_jobs();
        assert_eq!(state.queue_items[0].status, QueueStatus::Pending);
        assert!(state.queue_items[0].last_error.is_none());
        assert_eq!(state.queue_items[1].status, QueueStatus::Cancelled);
    }

    #[test]
    fn semver_compare_detects_newer_release() {
        assert_eq!(is_newer_version("0.3.0", "0.2.9"), Some(true));
        assert_eq!(is_newer_version("0.2.0", "0.2.0"), Some(false));
        assert_eq!(is_newer_version("v1.0.0", "0.9.9"), Some(true));
    }

    #[test]
    fn installer_asset_prefers_setup_before_msi() {
        let assets = vec![
            GitHubReleaseAsset {
                name: "PillowLock-0.2.0-portable-x64.exe".into(),
                browser_download_url: "https://example.com/PillowLock-portable.exe".into(),
            },
            GitHubReleaseAsset {
                name: "PillowLock-0.2.0-setup-x64.exe".into(),
                browser_download_url: "https://example.com/PillowLock-setup.exe".into(),
            },
            GitHubReleaseAsset {
                name: "PillowLock-0.2.0-x64.msi".into(),
                browser_download_url: "https://example.com/PillowLock.msi".into(),
            },
        ];
        let chosen = pick_installer_asset(&assets).expect("installer asset");
        assert!(chosen.name.ends_with("-setup-x64.exe"));
    }

    #[test]
    fn release_notes_excerpt_picks_first_non_empty_line() {
        let excerpt = release_notes_excerpt(Some("\n\nFirst line\nSecond line".into())).expect("excerpt");
        assert_eq!(excerpt, "First line");
    }
}
