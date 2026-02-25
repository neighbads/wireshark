/* expert_info_dialog.cpp
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "expert_info_dialog.h"
#include <ui_expert_info_dialog.h>

#include "file.h"

#include <epan/epan_dissect.h>
#include <epan/expert.h>
#include <epan/follow.h>
#include <epan/stat_tap_ui.h>
#include <epan/tap.h>

#include "progress_frame.h"
#include "main_application.h"

#include <QAction>
#include <QHash>
#include <QMenu>
#include <QMessageBox>
#include <QPushButton>

// To do:
// - Test with custom expert levels (Preferences -> Expert).
// - Test with large captures.
// - Promote to a fourth pane in the main window?
// - Make colors configurable? In theory we could condense image/expert_indicators.svg,
//   down to one item, make sure it uses a single (or a few) base color(s), and generate
//   icons on the fly.

ExpertInfoDialog::ExpertInfoDialog(QWidget &parent, CaptureFile &capture_file, QString displayFilter) :
    WiresharkDialog(parent, capture_file),
    ui(new Ui::ExpertInfoDialog),
    expert_info_model_(new ExpertInfoModel(capture_file)),
    proxyModel_(new ExpertInfoProxyModel(this)),
    display_filter_(displayFilter),
    self_retap_(true)
{
    ui->setupUi(this);
    ui->hintLabel->setSmallText();
    ui->limitCheckBox->setChecked(false);
    connect(ui->limitCheckBox, &QCheckBox::toggled,
            this, &ExpertInfoDialog::limitCheckBoxToggled);

    proxyModel_->setSourceModel(expert_info_model_);
    ui->expertInfoTreeView->setModel(proxyModel_);

    setWindowSubtitle(tr("Expert Information"));

    // Clicking on an item jumps to its associated packet. Make the dialog
    // narrow so that we avoid obscuring the packet list.
    int dlg_width = parent.width() * 3 / 5;
    if (dlg_width < width()) dlg_width = width();
    loadGeometry(dlg_width, parent.height());

    int one_em = fontMetrics().height();
    ui->expertInfoTreeView->setColumnWidth(ExpertInfoProxyModel::colProxySummary, one_em * 25); // Arbitrary

    //Unfortunately this has to be done manually and not through .ui
    ui->severitiesPushButton->setMenu(ui->menuShowExpert);

    ui->expertInfoTreeView->setContextMenuPolicy(Qt::CustomContextMenu);
    connect(ui->expertInfoTreeView, &ExpertInfoTreeView::customContextMenuRequested, this, &ExpertInfoDialog::showExpertInfoMenu);

    QMenu *submenu;

    FilterAction::Action cur_action = FilterAction::ActionApply;
    submenu = ctx_menu_.addMenu(FilterAction::actionName(cur_action));
    foreach (FilterAction::ActionType at, FilterAction::actionTypes()) {
        FilterAction *fa = new FilterAction(submenu, cur_action, at);
        submenu->addAction(fa);
        connect(fa, &FilterAction::triggered, this, &ExpertInfoDialog::filterActionTriggered);
    }

    cur_action = FilterAction::ActionPrepare;
    submenu = ctx_menu_.addMenu(FilterAction::actionName(cur_action));
    foreach (FilterAction::ActionType at, FilterAction::actionTypes()) {
        FilterAction *fa = new FilterAction(submenu, cur_action, at);
        submenu->addAction(fa);
        connect(fa, &FilterAction::triggered, this, &ExpertInfoDialog::filterActionTriggered);
    }

    FilterAction *fa;
    QList<FilterAction::Action> extra_actions =
            QList<FilterAction::Action>() << FilterAction::ActionFind
                                          << FilterAction::ActionColorize
                                          << FilterAction::ActionWebLookup
                                          << FilterAction::ActionCopy;

    foreach (FilterAction::Action extra_action, extra_actions) {
        fa = new FilterAction(&ctx_menu_, extra_action);
        ctx_menu_.addAction(fa);
        connect(fa, &FilterAction::triggered, this, &ExpertInfoDialog::filterActionTriggered);
    }

    //Add collapse/expand all menu options
    QAction *collapse = new QAction(tr("Collapse All"), this);
    ctx_menu_.addAction(collapse);
    connect(collapse, &QAction::triggered, this, &ExpertInfoDialog::collapseTree);

    QAction *expand = new QAction(tr("Expand All"), this);
    ctx_menu_.addAction(expand);
    connect(expand, &QAction::triggered, this, &ExpertInfoDialog::expandTree);

    connect(&cap_file_, &CaptureFile::captureEvent, this, &ExpertInfoDialog::captureEvent);

    // Disable Qt's built-in expand/collapse on double-click so our
    // treeDoubleClicked slot has sole control over the toggle.
    ui->expertInfoTreeView->setExpandsOnDoubleClick(false);

    connect(ui->expertInfoTreeView, &QTreeView::doubleClicked,
            this, &ExpertInfoDialog::treeDoubleClicked);

    ProgressFrame::addToButtonBox(ui->buttonBox, &parent);

    updateWidgets();
    QTimer::singleShot(0, this, &ExpertInfoDialog::retapPackets);
}

ExpertInfoDialog::~ExpertInfoDialog()
{
    delete ui;
    delete proxyModel_;
    delete expert_info_model_;
}

void ExpertInfoDialog::clearAllData()
{
    expert_info_model_->clear();
}

ExpertInfoTreeView* ExpertInfoDialog::getExpertInfoView()
{
    return ui->expertInfoTreeView;
}

void ExpertInfoDialog::retapPackets()
{
    if (file_closed_) return;

    clearAllData();
    removeTapListeners();

    if (!registerTapListener("expert",
                             expert_info_model_,
                             ui->limitCheckBox->isChecked() ? display_filter_.toUtf8().constData(): NULL,
                             TL_REQUIRES_COLUMNS,
                             ExpertInfoModel::tapReset,
                             ExpertInfoModel::tapPacket,
                             ExpertInfoModel::tapDraw)) {
        return;
    }

    self_retap_ = true;
    expert_info_model_->setIgnoreRetap(false);
    cap_file_.retapPackets();
    // cf_retap_packets is synchronous — Flushed/draw_tap_listeners already ran
    expert_info_model_->setIgnoreRetap(!ui->limitCheckBox->isChecked());
}

void ExpertInfoDialog::captureEvent(CaptureEvent e)
{
    if (e.captureContext() == CaptureEvent::Retap)
    {
        switch (e.eventType())
        {
        case CaptureEvent::Started:
            ui->limitCheckBox->setEnabled(false);
            ui->groupBySummaryCheckBox->setEnabled(false);
            if (!self_retap_) {
                expert_info_model_->setIgnoreRetap(true);
            }
            break;
        case CaptureEvent::Finished:
            self_retap_ = false;
            if (expert_info_model_->ignoreRetap()) {
                /* External retap — set ignoreRetap based on checkbox state. */
                expert_info_model_->setIgnoreRetap(!ui->limitCheckBox->isChecked());
                ui->limitCheckBox->setEnabled(!file_closed_ && !display_filter_.isEmpty());
                ui->groupBySummaryCheckBox->setEnabled(!file_closed_);
                return;
            }
            /* Self-initiated retap: don't set ignoreRetap here —
             * retapPackets() will do it after cap_file_.retapPackets()
             * returns, ensuring tapDraw runs first. */
            updateWidgets();
            break;
        default:
            break;
        }
    }
    else if (e.captureContext() == CaptureEvent::Rescan)
    {
        /* For external Rescan events (e.g. Follow Stream): if "Limit to
         * display filter" is checked, ignoreRetap is false and the rescan
         * refreshes data. If unchecked, ignoreRetap is true and data is
         * preserved. */
        switch (e.eventType())
        {
        case CaptureEvent::Started:
            ui->limitCheckBox->setEnabled(false);
            ui->groupBySummaryCheckBox->setEnabled(false);
            break;
        case CaptureEvent::Finished:
            display_filter_ = cap_file_.displayFilter();
            ui->limitCheckBox->setEnabled(!file_closed_ && !display_filter_.isEmpty());
            ui->groupBySummaryCheckBox->setEnabled(!file_closed_);
            updateWidgets();
            if (ui->limitCheckBox->isChecked()) {
                retapPackets();
            }
            break;
        default:
            break;
        }
    }
}

void ExpertInfoDialog::updateWidgets()
{
    ui->limitCheckBox->setEnabled(! file_closed_ && ! display_filter_.isEmpty());

    ui->actionShowError->setEnabled(expert_info_model_->numEvents(ExpertInfoModel::severityError) > 0);
    ui->actionShowWarning->setEnabled(expert_info_model_->numEvents(ExpertInfoModel::severityWarn) > 0);
    ui->actionShowNote->setEnabled(expert_info_model_->numEvents(ExpertInfoModel::severityNote) > 0);
    ui->actionShowChat->setEnabled(expert_info_model_->numEvents(ExpertInfoModel::severityChat) > 0);
    ui->actionShowComment->setEnabled(expert_info_model_->numEvents(ExpertInfoModel::severityComment) > 0);

    QString tooltip;
    QString hint;

    if (file_closed_) {
        tooltip = tr("Capture file closed.");
        hint = tr("Capture file closed.");
    } else if (display_filter_.isEmpty()) {
         tooltip = tr("No display filter");
         hint = tr("No display filter set.");
    } else {
        tooltip = tr("Limit information to \"%1\".").arg(display_filter_);
        hint = tr("Display filter: \"%1\"").arg(display_filter_);
    }

    ui->limitCheckBox->setToolTip(tooltip);
    ui->hintLabel->setText(hint);

    ui->groupBySummaryCheckBox->setEnabled(!file_closed_);
}

void ExpertInfoDialog::on_actionShowError_toggled(bool checked)
{
    proxyModel_->setSeverityFilter(PI_ERROR, !checked);
    updateWidgets();
}

void ExpertInfoDialog::on_actionShowWarning_toggled(bool checked)
{
    proxyModel_->setSeverityFilter(PI_WARN, !checked);
    updateWidgets();
}

void ExpertInfoDialog::on_actionShowNote_toggled(bool checked)
{
    proxyModel_->setSeverityFilter(PI_NOTE, !checked);
    updateWidgets();
}

void ExpertInfoDialog::on_actionShowChat_toggled(bool checked)
{
    proxyModel_->setSeverityFilter(PI_CHAT, !checked);
    updateWidgets();
}

void ExpertInfoDialog::on_actionShowComment_toggled(bool checked)
{
    proxyModel_->setSeverityFilter(PI_COMMENT, !checked);
    updateWidgets();
}


void ExpertInfoDialog::showExpertInfoMenu(QPoint pos)
{
    bool enable = true;
    QModelIndex expertIndex = ui->expertInfoTreeView->indexAt(pos);
    if (!expertIndex.isValid()) {
        return;
    }

    if (proxyModel_->data(expertIndex.sibling(expertIndex.row(), ExpertInfoModel::colHf), Qt::DisplayRole).toInt() < 0) {
        enable = false;
    }

    foreach (QMenu *submenu, ctx_menu_.findChildren<QMenu*>()) {
        submenu->setEnabled(enable && !file_closed_);
    }
    foreach (QAction *action, ctx_menu_.actions()) {
        FilterAction *fa = qobject_cast<FilterAction *>(action);
        bool action_enable = enable && !file_closed_;
        if (fa && (fa->action() == FilterAction::ActionWebLookup || fa->action() == FilterAction::ActionCopy)) {
            action_enable = enable;
        }
        action->setEnabled(action_enable);
    }

    // Build a dynamic Follow Stream submenu based on current packet's protocols
    QMenu *follow_menu = nullptr;
    if (!file_closed_ && cap_file_.capFile() && cap_file_.capFile()->edt) {
        wmem_list_t *layers = cap_file_.capFile()->edt->pi.layers;
        bool is_quic = proto_is_frame_protocol(layers, "quic");

        struct FollowMenuContext {
            QMenu *menu;
            wmem_list_t *layers;
            bool is_quic;
        } ctx = { nullptr, layers, is_quic };

        follow_iterate_followers(
            [](const void *key _U_, void *value, void *userdata) -> bool {
                register_follow_t *follow = (register_follow_t *)value;
                FollowMenuContext *ctx = (FollowMenuContext *)userdata;
                int proto_id = get_follow_proto_id(follow);
                const char *filter_name = proto_get_protocol_filter_name(proto_id);
                bool is_frame = proto_is_frame_protocol(ctx->layers, filter_name);
                // TLS is disabled when QUIC is present
                if (g_strcmp0(filter_name, "tls") == 0) {
                    is_frame = is_frame && !ctx->is_quic;
                }
                if (is_frame) {
                    if (!ctx->menu) {
                        ctx->menu = new QMenu();
                    }
                    QString proto_name = proto_get_protocol_short_name(find_protocol_by_id(proto_id));
                    QAction *action = ctx->menu->addAction(ExpertInfoDialog::tr("%1 Stream").arg(proto_name));
                    action->setData(proto_id);
                }
                return false;
            }, &ctx);

        follow_menu = ctx.menu;
    }

    // Build the final context menu with the dynamic follow submenu
    QMenu popup(this);
    foreach (QAction *action, ctx_menu_.actions()) {
        popup.addAction(action);
    }
    if (follow_menu) {
        popup.addSeparator();
        follow_menu->setTitle(tr("Follow"));
        popup.addMenu(follow_menu);
        connect(follow_menu, &QMenu::triggered, this, [this](QAction *action) {
            emit openFollowStreamDialog(action->data().toInt());
        });
    }

    popup.exec(ui->expertInfoTreeView->viewport()->mapToGlobal(pos));
    delete follow_menu;
}

void ExpertInfoDialog::filterActionTriggered()
{
    QModelIndex modelIndex = ui->expertInfoTreeView->currentIndex();
    FilterAction *fa = qobject_cast<FilterAction *>(QObject::sender());

    if (!fa || !modelIndex.isValid()) {
        return;
    }

    int hf_index = proxyModel_->data(modelIndex.sibling(modelIndex.row(), ExpertInfoModel::colHf), Qt::DisplayRole).toInt();

    if (hf_index > -1) {
        QString filter_string;
        if (fa->action() == FilterAction::ActionWebLookup) {
            filter_string = QStringLiteral("%1 %2")
                    .arg(proxyModel_->data(modelIndex.sibling(modelIndex.row(), ExpertInfoModel::colProtocol), Qt::DisplayRole).toString())
                    .arg(proxyModel_->data(modelIndex.sibling(modelIndex.row(), ExpertInfoModel::colSummary), Qt::DisplayRole).toString());
        } else if (fa->action() == FilterAction::ActionCopy) {
            filter_string = QStringLiteral("%1 %2: %3")
                    .arg(proxyModel_->data(modelIndex.sibling(modelIndex.row(), ExpertInfoModel::colPacket), Qt::DisplayRole).toUInt())
                    .arg(proxyModel_->data(modelIndex.sibling(modelIndex.row(), ExpertInfoModel::colProtocol), Qt::DisplayRole).toString())
                    .arg(proxyModel_->data(modelIndex.sibling(modelIndex.row(), ExpertInfoModel::colSummary), Qt::DisplayRole).toString());
        } else {
            filter_string = proto_registrar_get_abbrev(hf_index);
        }

        if (! filter_string.isEmpty()) {
            emit filterAction(filter_string, fa->action(), fa->actionType());
        }
    }
}

void ExpertInfoDialog::collapseTree()
{
    ui->expertInfoTreeView->collapseAll();
}

void ExpertInfoDialog::expandTree()
{
    ui->expertInfoTreeView->expandAll();
}

void ExpertInfoDialog::limitCheckBoxToggled(bool)
{
    retapPackets();
}

void ExpertInfoDialog::on_groupBySummaryCheckBox_toggled(bool)
{
    expert_info_model_->setGroupBySummary(ui->groupBySummaryCheckBox->isChecked());
}

// Show child (packet list) items that match the contents of searchLineEdit.
void ExpertInfoDialog::on_searchLineEdit_textChanged(const QString &search_re)
{
    proxyModel_->setSummaryFilter(search_re);
}

void ExpertInfoDialog::on_buttonBox_helpRequested()
{
    mainApp->helpTopicAction(HELP_EXPERT_INFO_DIALOG);
}

void ExpertInfoDialog::followStream()
{
    if (file_closed_ || !cap_file_.capFile())
        return;

    // Get the packet number from the current selection so we can ensure
    // the correct packet is selected before following.
    QModelIndex current = ui->expertInfoTreeView->currentIndex();
    if (!current.isValid() || !current.parent().isValid())
        return;
    QModelIndex source_index = proxyModel_->mapToSource(current);
    ExpertPacketItem *item = static_cast<ExpertPacketItem*>(source_index.internalPointer());
    if (!item)
        return;
    unsigned packet_num = item->packetNum();

    // The packet might not pass the current display filter (e.g., after a
    // previous follow stream set a filter like "tcp.stream eq 0"). Try
    // exact navigation first; if it fails, clear the filter and retry.
    if (!cf_goto_frame(cap_file_.capFile(), packet_num, true)) {
        cf_filter_packets(cap_file_.capFile(), NULL, true);
        if (!cf_goto_frame(cap_file_.capFile(), packet_num, true))
            return;
    }

    if (!cap_file_.capFile()->edt)
        return;

    // Find the first follow protocol that matches the current packet
    wmem_list_t *layers = cap_file_.capFile()->edt->pi.layers;
    bool is_quic = proto_is_frame_protocol(layers, "quic");

    struct FollowContext {
        wmem_list_t *layers;
        bool is_quic;
        int found_proto_id;
    } ctx = { layers, is_quic, -1 };

    follow_iterate_followers(
        [](const void *key _U_, void *value, void *userdata) -> bool {
            register_follow_t *follow = (register_follow_t *)value;
            FollowContext *ctx = (FollowContext *)userdata;
            if (ctx->found_proto_id >= 0)
                return false;
            int proto_id = get_follow_proto_id(follow);
            const char *filter_name = proto_get_protocol_filter_name(proto_id);
            bool is_frame = proto_is_frame_protocol(ctx->layers, filter_name);
            if (g_strcmp0(filter_name, "tls") == 0)
                is_frame = is_frame && !ctx->is_quic;
            if (is_frame)
                ctx->found_proto_id = proto_id;
            return false;
        }, &ctx);

    if (ctx.found_proto_id >= 0)
        emit openFollowStreamDialog(ctx.found_proto_id);
}

void ExpertInfoDialog::treeDoubleClicked(const QModelIndex &index)
{
    if (!index.isValid() || file_closed_)
        return;

    // Top-level item (severity group): toggle expand/collapse.
    // Use column 0 because QTreeView tracks expand state on that column only.
    if (!index.parent().isValid()) {
        QModelIndex col0 = index.siblingAtColumn(0);
        ui->expertInfoTreeView->setExpanded(col0,
            !ui->expertInfoTreeView->isExpanded(col0));
        return;
    }

    // Child item (packet-level): follow stream
    followStream();
}

// Stat command + args

static bool
expert_info_init(const char *, void*) {
    mainApp->emitStatCommandSignal("ExpertInfo", NULL, NULL);
    return true;
}

static stat_tap_ui expert_info_stat_ui = {
    REGISTER_STAT_GROUP_GENERIC,
    NULL,
    "expert",
    expert_info_init,
    0,
    NULL
};

extern "C" {

void register_tap_listener_qt_expert_info(void);

void
register_tap_listener_qt_expert_info(void)
{
    register_stat_tap_ui(&expert_info_stat_ui, NULL);
}

}
