use eframe::egui;
use chrono::Datelike;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

fn get_template(template_type: &str) -> Vec<&'static str> {
    match template_type {
        "web" => vec![
            "Planning & Design", "Backend Setup", "Frontend Development",
            "Authentication System", "Payment Integration", "Testing & QA", "Deployment",
        ],
        "mobile" => vec![
            "UI/UX Design", "Core Architecture", "User Authentication",
            "Main Features", "Push Notifications", "App Store Submission", "Marketing Launch",
        ],
        "api" => vec![
            "API Specification", "Database Design", "Authentication & Auth",
            "Core Endpoints", "Documentation", "Testing Suite", "Monitoring Setup",
        ],
        _ => vec![],
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct Feature {
    id: String,
    title: String,
    description: String,
    #[serde(default)]
    completed: bool,
    #[serde(default = "default_status")]
    status: String,
    #[serde(default = "default_color")]
    color: String,
}

fn default_status() -> String { "Planned".into() }
fn default_color() -> String { "#FF9800".into() }

#[derive(Clone, Debug, Serialize, Deserialize)]
struct Quarter {
    year: u32,
    quarter: u32,
    #[serde(default)]
    features: Vec<Feature>,
}

impl Quarter {
    fn new(year: u32, quarter: u32) -> Self {
        Self { year, quarter, features: Vec::new() }
    }

    fn name(&self) -> String {
        format!("Q{} {}", self.quarter, self.year)
    }

    fn date_range(&self) -> String {
        let months: [(u32, u32); 4] = [(1, 3), (4, 6), (7, 9), (10, 12)];
        let (start_month, end_month) = months[(self.quarter - 1) as usize];
        let start = chrono::NaiveDate::from_ymd_opt(self.year as i32, start_month, 1).unwrap();
        let end = if end_month == 12 {
            chrono::NaiveDate::from_ymd_opt(self.year as i32, 12, 31).unwrap()
        } else {
            chrono::NaiveDate::from_ymd_opt(self.year as i32, end_month + 1, 1).unwrap()
                - chrono::Duration::days(1)
        };
        format!("{} - {}", start.format("%b %d"), end.format("%b %d"))
    }
}

#[derive(Serialize, Deserialize)]
struct RoadmapFile {
    quarters: Vec<Quarter>,
}

struct FeatureDialogState {
    title: String,
    description: String,
    status: String,
    color: String,
}

impl Default for FeatureDialogState {
    fn default() -> Self {
        Self {
            title: String::new(),
            description: String::new(),
            status: "Planned".into(),
            color: default_color(),
        }
    }
}

impl FeatureDialogState {
    fn from_feature(f: &Feature) -> Self {
        Self {
            title: f.title.clone(),
            description: f.description.clone(),
            status: f.status.clone(),
            color: f.color.clone(),
        }
    }

    fn show(&mut self, ui: &mut egui::Ui) -> bool {
        let mut ok = false;
        ui.vertical(|ui| {
            ui.label("Title:");
            ui.text_edit_singleline(&mut self.title);
            ui.add_space(4.0);

            ui.label("Description:");
            ui.add(egui::TextEdit::multiline(&mut self.description).desired_rows(6));
            ui.add_space(4.0);

            ui.label("Status:");
            ui.horizontal(|ui| {
                for s in &["Planned", "Developing", "Testing", "Completed"] {
                    if ui.radio(self.status == *s, *s).clicked() {
                        self.status = s.to_string();
                    }
                }
            });
            ui.add_space(4.0);

            ui.label("Color:");
            ui.horizontal(|ui| {
                let colors = [
                    ("#F44336", egui::Color32::from_rgb(244, 67, 54)),   // Red
                    ("#FF9800", egui::Color32::from_rgb(255, 152, 0)),   // Orange
                    ("#FFEB3B", egui::Color32::from_rgb(255, 235, 59)),  // Yellow
                    ("#4CAF50", egui::Color32::from_rgb(76, 175, 80)),   // Green
                    ("#2196F3", egui::Color32::from_rgb(33, 150, 243)),  // Blue
                    ("#9C27B0", egui::Color32::from_rgb(156, 39, 176)),  // Purple
                    ("#E91E63", egui::Color32::from_rgb(233, 30, 99)),   // Pink
                    ("#00BCD4", egui::Color32::from_rgb(0, 188, 212)),   // Cyan
                ];
                for (hex, egui_color) in &colors {
                    let (rect, response) = ui.allocate_exact_size(
                        egui::vec2(20.0, 20.0),
                        egui::Sense::click(),
                    );
                    ui.painter().rect_filled(rect, 2.0, *egui_color);
                    if self.color == *hex {
                        ui.painter().rect_stroke(rect, 2.0, egui::Stroke::new(2.0, egui::Color32::WHITE));
                    }
                    if response.clicked() {
                        self.color = hex.to_string();
                    }
                    ui.add_space(4.0);
                }
            });
            ui.add_space(8.0);

            if ui.button("OK").clicked() {
                ok = true;
            }
        });
        ok
    }

    fn to_feature(&self, id: &str) -> Option<Feature> {
        if self.title.trim().is_empty() {
            return None;
        }
        Some(Feature {
            id: id.to_string(),
            title: self.title.trim().to_string(),
            description: self.description.trim().to_string(),
            completed: self.status == "Completed",
            status: self.status.clone(),
            color: self.color.clone(),
        })
    }
}

#[derive(Default)]
enum DialogState {
    #[default]
    None,
    AddFeature {
        quarter_idx: usize,
        dialog: FeatureDialogState,
    },
    EditFeature {
        quarter_idx: usize,
        feature_idx: usize,
        dialog: FeatureDialogState,
    },
    EditStatus {
        quarter_idx: usize,
        feature_idx: usize,
    },
}

enum DialogAction {
    OpenAddFeature(usize),
    OpenEditFeature(usize, usize),
    OpenEditStatus(usize, usize),
}

struct RoadmapApp {
    quarters: Vec<Quarter>,
    current_file: Option<PathBuf>,
    status_text: String,
    dialog_state: DialogState,
}

impl Default for RoadmapApp {
    fn default() -> Self {
        let mut app = Self {
            quarters: Vec::new(),
            current_file: None,
            status_text: "Ready".into(),
            dialog_state: DialogState::None,
        };
        app.initialize_quarters();
        app
    }
}

impl RoadmapApp {
    fn initialize_quarters(&mut self) {
        let now = chrono::Local::now();
        let current_year = now.year() as u32;
        let current_quarter = (now.month() - 1) / 3 + 1;
        for i in 0..4 {
            let mut q = current_quarter + i;
            let mut year = current_year;
            if q > 4 { q -= 4; year += 1; }
            self.quarters.push(Quarter::new(year, q));
        }
    }

    fn add_quarter(&mut self) {
        let (year, quarter) = if let Some(last) = self.quarters.last() {
            if last.quarter == 4 { (last.year + 1, 1) } else { (last.year, last.quarter + 1) }
        } else {
            let now = chrono::Local::now();
            (now.year() as u32, 1)
        };
        self.quarters.push(Quarter::new(year, quarter));
        self.status_text = format!("Added Q{} {}", quarter, year);
    }

    fn remove_quarter(&mut self, index: usize) {
        if index < self.quarters.len() {
            let removed = self.quarters.remove(index);
            self.status_text = format!("Removed {}", removed.name());
        }
    }

    fn clear_all(&mut self) {
        self.quarters.clear();
        self.status_text = "Cleared all quarters".into();
    }

    fn new_roadmap(&mut self) {
        self.quarters.clear();
        self.current_file = None;
        self.initialize_quarters();
        self.status_text = "New roadmap created".into();
    }

    fn open_roadmap(&mut self) {
        if let Some(path) = rfd::FileDialog::new().add_filter("JSON", &["json"]).pick_file() {
            match std::fs::read_to_string(&path) {
                Ok(data) => match serde_json::from_str::<RoadmapFile>(&data) {
                    Ok(file) => {
                        self.quarters = file.quarters;
                        self.current_file = Some(path);
                        self.status_text = "Opened roadmap".into();
                    }
                    Err(e) => self.status_text = format!("Error parsing: {}", e),
                },
                Err(e) => self.status_text = format!("Error reading: {}", e),
            }
        }
    }

    fn save_roadmap(&mut self) {
        if let Some(ref path) = self.current_file {
            self.save_to_file(path.clone());
        } else {
            self.save_as_roadmap();
        }
    }

    fn save_as_roadmap(&mut self) {
        if let Some(path) = rfd::FileDialog::new().add_filter("JSON", &["json"]).set_file_name("roadmap.json").save_file() {
            self.save_to_file(path);
        }
    }

    fn save_to_file(&mut self, path: PathBuf) {
        let file = RoadmapFile { quarters: self.quarters.clone() };
        match serde_json::to_string_pretty(&file) {
            Ok(json) => match std::fs::write(&path, json) {
                Ok(_) => { self.current_file = Some(path); self.status_text = "Saved roadmap".into(); }
                Err(e) => self.status_text = format!("Error saving: {}", e),
            },
            Err(e) => self.status_text = format!("Error serializing: {}", e),
        }
    }

    fn load_template(&mut self, template_type: &str) {
        self.quarters.clear();
        let now = chrono::Local::now();
        let year = now.year() as u32;
        let features = get_template(template_type);
        let per_q = 2;
        let num_q = (features.len() + per_q - 1) / per_q;
        for i in 0..num_q {
            let mut q = Quarter::new(year, (i as u32) + 1);
            let start = i * per_q;
            let end = std::cmp::min(start + per_q, features.len());
            for (j, title) in features[start..end].iter().enumerate() {
                let colors = ["#4CAF50", "#2196F3", "#FF9800", "#9C27B0"];
                q.features.push(Feature {
                    id: format!("feature_{}_{}_{}", template_type, i, j),
                    title: title.to_string(),
                    description: format!("Implementation of {}", title),
                    completed: false,
                    status: "Planned".into(),
                    color: colors[i % colors.len()].into(),
                });
            }
            self.quarters.push(q);
        }
        self.status_text = format!("Loaded {} template", template_type);
    }
}

fn parse_color(hex: &str) -> egui::Color32 {
    let hex = hex.trim_start_matches('#');
    if hex.len() == 6 {
        if let Ok(r) = u8::from_str_radix(&hex[0..2], 16) {
            if let Ok(g) = u8::from_str_radix(&hex[2..4], 16) {
                if let Ok(b) = u8::from_str_radix(&hex[4..6], 16) {
                    return egui::Color32::from_rgb(r, g, b);
                }
            }
        }
    }
    egui::Color32::from_rgb(33, 150, 243)
}

impl eframe::App for RoadmapApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        egui::TopBottomPanel::top("title_bar").show(ctx, |ui| {
            let available = ui.available_rect_before_wrap();
            let drag_rect = available.intersect(ui.max_rect());
            let drag_response = ui.interact(drag_rect, ui.id().with("drag_area"), egui::Sense::drag());

            if drag_response.dragged() {
                ctx.send_viewport_cmd(egui::ViewportCommand::StartDrag);
            }

            egui::menu::bar(ui, |ui| {
                ui.label(egui::RichText::new("allroads").strong().size(14.0));
                ui.add_space(16.0);
                ui.menu_button("File", |ui| {
                    if ui.button("New").clicked() { self.new_roadmap(); ui.close_menu(); }
                    if ui.button("Open").clicked() { self.open_roadmap(); ui.close_menu(); }
                    if ui.button("Save").clicked() { self.save_roadmap(); ui.close_menu(); }
                    if ui.button("Save As").clicked() { self.save_as_roadmap(); ui.close_menu(); }
                    if ui.button("Exit").clicked() { ctx.send_viewport_cmd(egui::ViewportCommand::Close); }
                });
                ui.menu_button("Templates", |ui| {
                    if ui.button("Web Application").clicked() { self.load_template("web"); ui.close_menu(); }
                    if ui.button("Mobile App").clicked() { self.load_template("mobile"); ui.close_menu(); }
                    if ui.button("API Development").clicked() { self.load_template("api"); ui.close_menu(); }
                });

                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    if ui.button("Close").clicked() {
                        ctx.send_viewport_cmd(egui::ViewportCommand::Close);
                    }
                    if ui.button("Minimize").clicked() {
                        ctx.send_viewport_cmd(egui::ViewportCommand::Minimized(true));
                    }
                });
            });
        });

        egui::TopBottomPanel::bottom("status_bar").show(ctx, |ui| {
            ui.label(&self.status_text);
        });

        egui::TopBottomPanel::top("controls").show(ctx, |ui| {
            ui.horizontal(|ui| {
                ui.heading("Timeline");
                ui.add_space(10.0);
                if ui.button("Add Quarter").clicked() { self.add_quarter(); }
                if ui.button("Clear All").clicked() { self.clear_all(); }
            });
        });

        egui::CentralPanel::default().show(ctx, |ui| {
            egui::ScrollArea::vertical().show(ui, |ui| {
                let mut dialog_action: Option<DialogAction> = None;
                let mut remove_action: Option<(usize, usize)> = None;
                let mut move_up_action: Option<(usize, usize)> = None;
                let mut move_down_action: Option<(usize, usize)> = None;
                let mut quarter_remove_idx: Option<usize> = None;

                for (qi, quarter) in &mut self.quarters.iter_mut().enumerate() {
                    egui::Frame::group(ui.style())
                        .stroke(egui::Stroke::new(1.0, egui::Color32::from_rgb(180, 180, 180)))
                        .show(ui, |ui| {
                            ui.vertical(|ui| {
                                ui.horizontal(|ui| {
                                    ui.heading(quarter.name());
                                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                                        if ui.small_button("x").clicked() {
                                            quarter_remove_idx = Some(qi);
                                        }
                                    });
                                });
                                ui.label(quarter.date_range());
                                ui.separator();

                                if ui.button("+ Add Feature").clicked() {
                                    dialog_action = Some(DialogAction::OpenAddFeature(qi));
                                }

                                ui.add_space(4.0);

                                for (fi, feature) in quarter.features.iter().enumerate() {
                                    egui::Frame::none()
                                        .stroke(egui::Stroke::new(0.5, egui::Color32::from_rgb(200, 200, 200)))
                                        .inner_margin(4.0)
                                        .outer_margin(0.0)
                                        .show(ui, |ui| {
                                        let available = ui.available_width();
                                        ui.allocate_ui(egui::vec2(available, 36.0), |ui| {
                                            ui.horizontal(|ui| {
                                                let color = parse_color(&feature.color);
                                                let (rect, _) = ui.allocate_exact_size(
                                                    egui::vec2(6.0, 28.0),
                                                    egui::Sense::hover(),
                                                );
                                                ui.painter().rect_filled(rect, 0.0, color);

                                                if feature.completed {
                                                    ui.colored_label(egui::Color32::GRAY, &feature.title);
                                                } else {
                                                    ui.label(&feature.title);
                                                }

                                                let status_color = if feature.completed {
                                                    egui::Color32::from_rgb(76, 175, 80)
                                                } else {
                                                    egui::Color32::from_rgb(100, 100, 100)
                                                };
                                                let status_response = ui.colored_label(status_color, format!("[{}]", feature.status));
                                                if status_response.clicked() {
                                                    dialog_action = Some(DialogAction::OpenEditStatus(qi, fi));
                                                }

                                                ui.colored_label(egui::Color32::GRAY, &feature.description);

                                                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                                                    if ui.small_button("Down").clicked() {
                                                        move_down_action = Some((qi, fi));
                                                    }
                                                    if ui.small_button("Up").clicked() {
                                                        move_up_action = Some((qi, fi));
                                                    }
                                                    if ui.small_button("Delete").clicked() {
                                                        remove_action = Some((qi, fi));
                                                    }
                                                    if ui.small_button("Edit").clicked() {
                                                        dialog_action = Some(DialogAction::OpenEditFeature(qi, fi));
                                                    }
                                                });
                                            });
                                        });
                                    });
                                }
                            });
                        });
                    ui.add_space(8.0);
                }

                if let Some(qi) = quarter_remove_idx {
                    self.remove_quarter(qi);
                }

                if let Some((qi, fi)) = remove_action {
                    self.quarters[qi].features.remove(fi);
                }
                if let Some((qi, fi)) = move_up_action {
                    if fi > 0 {
                        self.quarters[qi].features.swap(fi, fi - 1);
                    } else if qi > 0 {
                        let feature = self.quarters[qi].features.remove(fi);
                        self.quarters[qi - 1].features.push(feature);
                    }
                }
                if let Some((qi, fi)) = move_down_action {
                    if fi < self.quarters[qi].features.len() - 1 {
                        self.quarters[qi].features.swap(fi, fi + 1);
                    } else if qi < self.quarters.len() - 1 {
                        let feature = self.quarters[qi].features.remove(fi);
                        self.quarters[qi + 1].features.insert(0, feature);
                    }
                }

                if let Some(action) = dialog_action {
                    match action {
                        DialogAction::OpenAddFeature(qi) => {
                            self.dialog_state = DialogState::AddFeature {
                                quarter_idx: qi,
                                dialog: FeatureDialogState::default(),
                            };
                        }
                        DialogAction::OpenEditFeature(qi, fi) => {
                            let existing = &self.quarters[qi].features[fi];
                            self.dialog_state = DialogState::EditFeature {
                                quarter_idx: qi,
                                feature_idx: fi,
                                dialog: FeatureDialogState::from_feature(existing),
                            };
                        }
                        DialogAction::OpenEditStatus(qi, fi) => {
                            self.dialog_state = DialogState::EditStatus {
                                quarter_idx: qi,
                                feature_idx: fi,
                            };
                        }
                    }
                }
            });
        });

        let mut close_dialog = false;
        let mut new_status = None;

        match &mut self.dialog_state {
            DialogState::AddFeature { quarter_idx, dialog } => {
                let qi = *quarter_idx;
                egui::Window::new("Add Feature").collapsible(false).resizable(false).show(ctx, |ui| {
                    if dialog.show(ui) {
                        if let Some(feat) = dialog.to_feature(&format!("feature_{}", self.quarters[qi].features.len())) {
                            self.quarters[qi].features.push(feat);
                            self.status_text = format!("Added feature: {}", self.quarters[qi].features.last().unwrap().title);
                        }
                        close_dialog = true;
                    }
                    if ui.button("Cancel").clicked() {
                        close_dialog = true;
                    }
                });
            }
            DialogState::EditFeature { quarter_idx, feature_idx, dialog } => {
                let (qi, fi) = (*quarter_idx, *feature_idx);
                let existing_id = self.quarters[qi].features[fi].id.clone();
                egui::Window::new("Edit Feature").collapsible(false).resizable(false).show(ctx, |ui| {
                    if dialog.show(ui) {
                        if let Some(feat) = dialog.to_feature(&existing_id) {
                            self.quarters[qi].features[fi] = feat;
                            self.status_text = format!("Updated feature: {}", self.quarters[qi].features[fi].title);
                        }
                        close_dialog = true;
                    }
                    if ui.button("Cancel").clicked() {
                        close_dialog = true;
                    }
                });
            }
            DialogState::EditStatus { quarter_idx, feature_idx } => {
                let (qi, fi) = (*quarter_idx, *feature_idx);
                let mut status = self.quarters[qi].features[fi].status.clone();
                egui::Window::new("Edit Status").collapsible(false).resizable(false).show(ctx, |ui| {
                    ui.vertical(|ui| {
                        for s in &["Planned", "Developing", "Testing", "Completed"] {
                            if ui.radio(status == *s, *s).clicked() {
                                status = s.to_string();
                            }
                        }
                        ui.horizontal(|ui| {
                            if ui.button("OK").clicked() {
                                new_status = Some((qi, fi, status.clone()));
                                close_dialog = true;
                            }
                            if ui.button("Cancel").clicked() {
                                close_dialog = true;
                            }
                        });
                    });
                });
            }
            DialogState::None => {}
        }

        if close_dialog {
            self.dialog_state = DialogState::None;
        }
        if let Some((qi, fi, status)) = new_status {
            self.quarters[qi].features[fi].status = status.clone();
            self.quarters[qi].features[fi].completed = status == "Completed";
            self.status_text = format!("Updated status to: {}", status);
        }
    }
}

fn main() -> eframe::Result<()> {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([1200.0, 700.0])
            .with_title("AllRoads v1.0")
            .with_decorations(false),
        ..Default::default()
    };
    eframe::run_native(
        "AllRoads",
        options,
        Box::new(|_cc| Ok(Box::new(RoadmapApp::default()))),
    )
}
