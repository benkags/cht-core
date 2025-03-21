import { Component, EventEmitter, OnDestroy, OnInit, Output, ViewChild } from '@angular/core';
import { Data, NavigationStart, Router, RouterLink } from '@angular/router';
import { combineLatest, Subscription } from 'rxjs';
import { filter } from 'rxjs/operators';
import { Store } from '@ngrx/store';
import { MatBottomSheet, MatBottomSheetRef } from '@angular/material/bottom-sheet';
import { MatDialog, MatDialogRef } from '@angular/material/dialog';

import { Selectors } from '@mm-selectors/index';
import { AuthService } from '@mm-services/auth.service';
import { GlobalActions } from '@mm-actions/global';
import { ResponsiveService } from '@mm-services/responsive.service';
import { ReportsActions } from '@mm-actions/reports';
import { NgIf } from '@angular/common';
import { MatIconButton, MatButton } from '@angular/material/button';
import { MatMenuTrigger, MatMenu, MatMenuItem } from '@angular/material/menu';
import { MatIcon } from '@angular/material/icon';
import { PanelHeaderComponent } from '@mm-components/panel-header/panel-header.component';
import {
  ReportVerifyInvalidIconComponent,
  ReportVerifyValidIconComponent
} from '@mm-components/status-icons/status-icons.template';
import { TranslatePipe } from '@ngx-translate/core';


@Component({
  selector: 'mm-reports-more-menu',
  templateUrl: './reports-more-menu.component.html',
  imports: [
    NgIf,
    MatIconButton,
    MatMenuTrigger,
    MatIcon,
    MatMenu,
    MatMenuItem,
    RouterLink,
    PanelHeaderComponent,
    MatButton,
    ReportVerifyInvalidIconComponent,
    ReportVerifyValidIconComponent,
    TranslatePipe
  ]
})
export class ReportsMoreMenuComponent implements OnInit, OnDestroy {
  @Output() exportReports: EventEmitter<any> = new EventEmitter();
  @ViewChild('verifyReportWrapper') verifyReportWrapper;

  private reportsActions: ReportsActions;
  private globalActions: GlobalActions;
  private hasExportPermission = false;
  private hasEditPermission = false;
  private hasDeletePermission = false;
  private hasVerifyPermission = false;
  private hasEditVerifyPermission = false;
  private hasUpdatePermission = false;
  private selectMode = false;
  private loadingContent?: boolean;
  private snapshotData: Data | null = null;
  private isOnlineOnly?: boolean;
  private dialogRef: MatDialogRef<any> | undefined;
  private bottomSheetRef: MatBottomSheetRef<any> | undefined;

  subscription: Subscription = new Subscription();
  reportsList;
  selectedReportDoc;
  verifyingReport = false;
  processingReportVerification = false;
  direction;

  constructor(
    private store: Store,
    private router: Router,
    private authService: AuthService,
    private responsiveService: ResponsiveService,
    private matBottomSheet: MatBottomSheet,
    private matDialog: MatDialog,
  ) {
    this.globalActions = new GlobalActions(store);
    this.reportsActions = new ReportsActions(store);
  }

  ngOnInit(): void {
    this.subscribeToStore();
    this.checkPermissions();
    this.subscribeToRouter();
    this.isOnlineOnly = this.authService.online(true);
  }

  ngOnDestroy(): void {
    this.subscription.unsubscribe();
  }

  private subscribeToStore() {
    const storeSubscription = combineLatest(
      this.store.select(Selectors.getReportsList),
      this.store.select(Selectors.getSnapshotData),
      this.store.select(Selectors.getLoadingContent),
      this.store.select(Selectors.getSelectedReportDoc),
      this.store.select(Selectors.getSelectMode),
      this.store.select(Selectors.getVerifyingReport),
      this.store.select(Selectors.getProcessingReportVerification),
      this.store.select(Selectors.getDirection),
    ).subscribe(([
      reportsList,
      snapshotData,
      loadingContent,
      selectedReportDoc,
      selectMode,
      verifyingReport,
      processingReportVerification,
      direction,
    ]) => {
      this.reportsList = reportsList;
      this.snapshotData = snapshotData;
      this.loadingContent = loadingContent;
      this.selectedReportDoc = selectedReportDoc;
      this.selectMode = selectMode;
      this.verifyingReport = verifyingReport;
      this.processingReportVerification = processingReportVerification;
      this.direction = direction;
    });
    this.subscription.add(storeSubscription);
  }

  private subscribeToRouter() {
    const routerSubscription = this.router.events
      .pipe(filter(event => event instanceof NavigationStart))
      .subscribe(() => this.closeVerifyReportComponents());
    this.subscription.add(routerSubscription);
  }

  private async checkPermissions() {
    this.hasEditPermission = await this.authService.has('can_edit');
    this.hasUpdatePermission = await this.authService.has('can_update_reports');
    this.hasDeletePermission = await this.authService.has('can_delete_reports');
    this.hasExportPermission = await this.authService.any([[ 'can_export_all' ], [ 'can_export_messages' ]]);
    this.hasVerifyPermission = await this.authService.has('can_verify_reports');
    this.hasEditVerifyPermission = await this.authService.has('can_edit_verification');
  }

  deleteReport() {
    this.globalActions.deleteDocConfirm(this.selectedReportDoc);
  }

  displayDeleteOption() {
    return this.selectedReportDoc
      && !this.selectMode
      && !this.loadingContent
      && this.hasEditPermission
      && this.hasDeletePermission
      && this.snapshotData?.name === 'reports.detail';
  }

  displayEditOption() {
    return this.selectedReportDoc
      && !this.selectMode
      && !this.loadingContent
      && this.hasEditPermission
      && this.hasUpdatePermission
      && this.snapshotData?.name === 'reports.detail'
      && this.selectedReportDoc?.content_type === 'xml';
  }

  displayExportOption() {
    return !this.selectMode && this.isOnlineOnly && this.hasExportPermission && !this.responsiveService.isMobile();
  }

  displayVerifyReportOption() {
    const hasFullPermissions = this.hasEditVerifyPermission && this.hasVerifyPermission;
    const hasPartialPermissions = this.selectedReportDoc?.verified === undefined && this.hasVerifyPermission;

    return this.selectedReportDoc
      && !this.selectMode
      && !this.loadingContent
      && this.snapshotData?.name === 'reports.detail'
      && this.hasEditPermission
      && (hasFullPermissions || hasPartialPermissions);
  }

  isReportCorrect(isCorrect: boolean) {
    this.reportsActions.verifyReport(isCorrect);
    this.closeVerifyReportComponents();
  }

  openVerifyReportOptions() {
    this.closeVerifyReportComponents();

    if (this.responsiveService.isMobile()) {
      this.bottomSheetRef = this.matBottomSheet.open(this.verifyReportWrapper);
      return;
    }

    this.dialogRef = this.matDialog.open(this.verifyReportWrapper, {
      autoFocus: false,
      minWidth: 300,
      minHeight: 150,
      direction: this.direction,
    });
  }

  closeVerifyReportComponents() {
    if (this.bottomSheetRef) {
      this.bottomSheetRef.dismiss();
      this.bottomSheetRef = undefined;
    }

    if (this.dialogRef) {
      this.dialogRef.close();
      this.dialogRef = undefined;
    }
  }
}
