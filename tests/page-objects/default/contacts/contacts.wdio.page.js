const genericForm = require('@page-objects/default/enketo/generic-form.wdio.page');
const commonPage = require('@page-objects/default/common/common.wdio.page');
const sentinelUtils = require('@utils/sentinel');
const utils = require('@utils');
const modalPage = require('@page-objects/default/common/modal.wdio.page');
const searchPage = require('@page-objects/default/search/search.wdio.page');
const mobileSearchPage = require('@page-objects/default-mobile/search/search.wdio.page');
const commonEnketoPage = require('@page-objects/default/enketo/common-enketo.wdio.page');

const searchSelectors = {
  searchBox: () => $('.mm-search-bar-container input#freetext'),
};

const CONTACT_LIST_SELECTOR = '#contacts-list';
const CONTENT_ROW_SELECTOR =  `${CONTACT_LIST_SELECTOR} .content-row`;
const leftPanelSelectors = {
  contactList: () => $(CONTACT_LIST_SELECTOR),
  contentRow: () => $(CONTENT_ROW_SELECTOR),
  contentRows: () =>  $$(CONTENT_ROW_SELECTOR),
  contactName: () => $$(`${CONTENT_ROW_SELECTOR} .heading h4 span`),
  contactListLoadingStatus: () => $(`${CONTACT_LIST_SELECTOR} .loading-status`),
  firstContact: () => $(`${CONTACT_LIST_SELECTOR} li:first-child`),
};

const rightPanelSelectors = {
  emptySelection: () => $('contacts-content .empty-selection'),
  childrenCards: () => $$('.right-pane .card.children'),
  contactCardTitle: () => $('.inbox .content-pane .material .body .action-header'),
};

const contactCardSelectors = {
  contactCardName: () => $('h2[test-id="contact-name"]'),
  contactCardIcon: (name) => $(`.card .heading .resource-icon[title="medic-${name}"]`),
  contactSummaryContainer: () => $('#contact_summary'),
  contactMedicID: () => $('#contact_summary .cell.patient_id > div > p:not(.summary_label)'),
  contactDeceasedStatus: () => $('div[test-id="deceased-title"]'),
  contactMuted: () => $('.heading-content .muted'),
};

const peopleCardSelectors = {
  primaryContactName: () => $('i[title="Primary contact"]').nextElement(),
  rhsPeopleListSelector: () => $$('.card.children.persons h4 span'),
};

const RHS_TASK_LIST_CARD =  '.card.tasks';
const TASK_FILTER_SELECTOR = `${RHS_TASK_LIST_CARD} .table-filter a`;
const RHS_TASK_LIST_SELECTOR = `${RHS_TASK_LIST_CARD} mm-content-row h4 span`;
const tasksCardSelectors = {
  taskFilter: () => $(TASK_FILTER_SELECTOR),
  taskFilters: () => $$(TASK_FILTER_SELECTOR),
  rhsTaskListElement: () =>  $(RHS_TASK_LIST_SELECTOR),
  rhsTaskListElementList: () => $$(RHS_TASK_LIST_SELECTOR),
};

const RHS_REPORT_LIST_CARD = '.card.reports';
const REPORT_FILTER_SELECTOR = `${RHS_REPORT_LIST_CARD} .table-filter a`;
const RHS_REPORT_LIST_SELECTOR = `${RHS_REPORT_LIST_CARD} mm-content-row h4 span`;
const reportsCardSelectors = {
  reportFilter: () => $(REPORT_FILTER_SELECTOR),
  reportFilters: () => $$(REPORT_FILTER_SELECTOR),
  rhsReportListElement: () => $(RHS_REPORT_LIST_SELECTOR),
  rhsReportElementList: () => $$(RHS_REPORT_LIST_SELECTOR),
};

const PREG_CARD_TEST_ID = `div[test-id="contact.profile.pregnancy.active"]`;
const pregnancyCardSelectors = {
  pregnancyCard: () => $(PREG_CARD_TEST_ID),
  weeksPregnant: () => $(`${PREG_CARD_TEST_ID} div[test-id="Weeks Pregnant"] p.card-field-value`),
  edd: () => $(`${PREG_CARD_TEST_ID} div[test-id="contact.profile.edd"] p.card-field-value`),
  highRisk: () => $(`${PREG_CARD_TEST_ID} div[test-id="contact.profile.risk.high"] label`),
  nextANCVisit: () => $(`${PREG_CARD_TEST_ID} div[test-id="contact.profile.anc.next"] p.card-field-value`),
};

const DEATH_CARD_TEST_ID = 'div[test-id="contact.profile.death.title"]';
const deathCardSelectors = {
  deathCard: () => $(DEATH_CARD_TEST_ID),
  deathDate: () => $(`${DEATH_CARD_TEST_ID} div[test-id="contact.profile.death.date"] p.card-field-value`),
  deathPlace: () => $(`${DEATH_CARD_TEST_ID} div[test-id="contact.profile.death.place"] p.card-field-value`),
};

const inmunizationCardSelectors = {
  inmunizationCard: () => $('div[test-id="contact.profile.immunizations"]'),
};

const editDistrictHospitalSelectors = {
  primaryContactSearchDropdown: () => $( 'span.select2-selection--single' +
    '[aria-labelledby^="select2-/data/district_hospital/contact/_id"]'),
  primaryContactSearchInput: () => $('input.select2-search__field'),
  primaryContactSearchFirstResult: () => $('.select2-results__option--highlighted'),
};

const sortMenuSelectors = {
  sortIcon: () => $('#sort-results'),
  sortDropdown: () => $('#sort-results-dropdown'),
  sortMenuItems: () => $$('#sort-results-dropdown a[role="menuitem"]'),
};

const openSortMenu = async () => {
  await sortMenuSelectors.sortIcon().click();
  await sortMenuSelectors.sortDropdown().waitForDisplayed();
};

const selectSortOrder = async (sortLabel) => {
  await openSortMenu();
  const option = await sortMenuSelectors.sortDropdown().$(`a[role="menuitem"]*=${sortLabel}`);
  if (await option.isExisting()) {
    await option.click();
  } else {
    throw new Error(`Sort option "${sortLabel}" not found`);
  }
};

const search = async (query) => {
  if (!await searchSelectors.searchBox().isDisplayed()) {
    await mobileSearchPage.performSearch(query);
  } else {
    await searchPage.performSearch(query);
  }
};

const findRowByText = async (text, strict) => {
  for (const row of await leftPanelSelectors.contentRows()) {
    const rowText = await row.getText();
    if ((strict && rowText === text) || (!strict && rowText.includes(text))) {
      return row;
    }
  }
};

const selectLHSRowByText = async (text, executeSearch = true, strict = true) => {
  await commonPage.waitForLoaderToDisappear();
  if (executeSearch) {
    await search(text);
  }
  await browser.waitUntil(async () => await findRowByText(text, strict));
  const row = await findRowByText(text, strict);
  if (!row) {
    throw new Error(`Contact "${text}" was not found`);
  }
  await row.click();
  await waitForContactLoaded();
};

const selectRHSRowById = async (id) => {
  const contact = await $(`.card.children.persons .content-row > a[href="#/contacts/${id}"]`);
  await contact.click();
  await waitForContactLoaded();
};

const getReportFiltersText = async () => {
  await reportsCardSelectors.reportFilter().waitForDisplayed();
  return reportsCardSelectors.reportFilters().map(filter => filter.getText());
};

const getReportTaskFiltersText = async () => {
  await tasksCardSelectors.taskFilter().waitForDisplayed();
  return await tasksCardSelectors.taskFilters().map(filter => filter.getText());
};

const waitForContactLoaded = async (type) => {
  type && await contactCardSelectors.contactCardIcon(type).waitForDisplayed();
  await contactCardSelectors.contactCardName().waitForDisplayed();
  await contactCardSelectors.contactSummaryContainer().waitForDisplayed();
};

const waitForContactUnloaded = async () => {
  await rightPanelSelectors.emptySelection().waitForDisplayed();
};

const addPlace = async (
  {
    type: typeValue = 'district_hospital',
    placeName: placeNameValue = 'District Test',
    contactName: contactNameValue = 'Person1',
    dob: dobValue = '2000-01-01',
    phone: phoneValue = '',
    sex: sexValue = 'Female',
    role: roleValue = 'CHW',
    externalID: externalIDValue = '12345678',
    notes: notesValue = 'Some test notes',
  } = {},
  {
    rightSideAction = true,
    waitForComplete = true
  } = {}
) => {

  if (rightSideAction) {
    await commonPage.clickFastActionFAB({ actionId: typeValue });
  } else {
    await commonPage.clickFastActionFlat({ waitForList: false });
  }
  await commonEnketoPage.selectRadioButton('Set the Primary Contact', 'Create a new person');
  await commonEnketoPage.setInputValue('Full Name', contactNameValue);
  await commonEnketoPage.setInputValue('Phone Number', phoneValue);
  await commonEnketoPage.setDateValue('Age', dobValue);
  await commonEnketoPage.selectRadioButton('Sex', sexValue);
  await commonEnketoPage.selectRadioButton('Role', roleValue);
  await genericForm.nextPage();
  await commonEnketoPage.selectRadioButton(
    'Would you like to name the place after the primary contact:',
    'No, I want to name it manually'
  );
  await commonEnketoPage.setInputValue('Name', placeNameValue);
  await commonEnketoPage.setInputValue('External ID', externalIDValue);
  await commonEnketoPage.setTextareaValue('Notes', notesValue);
  await genericForm.submitForm({ waitForPageLoaded: false });

  if (waitForComplete) {
    const dashedType = typeValue.replace('_', '-');
    await waitForContactLoaded(dashedType);
  }
};

const addPerson = async (
  {
    name: nameValue = 'Person1',
    dob: dobValue = '2000-01-01',
    phone: phoneValue = '',
    sex: sexValue = 'Female',
    role: roleValue = 'CHW',
    externalID: externalIDValue = '12345678',
    notes: notesValue = 'Some test notes',
  } = {},
  {
    waitForSentinel = true,
    waitForComplete = true
  } = {}
) => {
  const type = 'person';
  await commonPage.clickFastActionFAB({ actionId: type });
  await commonEnketoPage.setInputValue('Full name', nameValue);
  await commonEnketoPage.setInputValue('Phone Number', phoneValue);
  await commonEnketoPage.selectRadioButton('Sex', sexValue);
  await commonEnketoPage.selectRadioButton('Role', roleValue);
  await commonEnketoPage.setDateValue('Age', dobValue);
  await commonEnketoPage.setInputValue('External ID', externalIDValue);
  await commonEnketoPage.setTextareaValue('Notes', notesValue);
  await genericForm.submitForm();
  if (waitForSentinel) {
    await sentinelUtils.waitForSentinel();
  }
  if (waitForComplete) {
    await contactCardSelectors.contactCardIcon(type).waitForDisplayed();
    return contactCardSelectors.contactCardName().getText();
  }
};

const editPerson = async (currentName, { name, phone, dob }) => {
  await selectLHSRowByText(currentName);
  await commonPage.accessEditOption();
  await genericForm.nextPage();

  if (name !== undefined) {
    await commonEnketoPage.setInputValue('Full name', name);
  }
  if (phone !== undefined) {
    await commonEnketoPage.setInputValue('Phone Number', phone);
  }
  if (dob !== undefined) {
    await commonEnketoPage.setDateValue('Age', dob);
  }
  await genericForm.formTitle().click();
  await genericForm.submitForm();
};

const editPersonName = async (name, updatedName) => {
  await editPerson(name, { name: updatedName });
  return (await contactCardSelectors.contactCardName()).getText();
};

const deletePerson = async () => {
  await commonPage.accessDeleteOption();
  await modalPage.submit();
};

const getContactSummaryField = async (fieldName) => {
  await contactCardSelectors.contactSummaryContainer().waitForDisplayed();
  const field = await contactCardSelectors.contactSummaryContainer()
    .$(`.cell.${fieldName.toLowerCase().replace(/\./g, '\\.')}`);
  return await  field.$('p:not(.summary_label)').getText();
};

const getPrimaryContactName = async () => {
  return await peopleCardSelectors.primaryContactName().getText();
};

const getAllLHSContactsNames = async () => {
  await leftPanelSelectors.contentRow().waitForDisplayed();
  return commonPage.getTextForElements(leftPanelSelectors.contactName);
};

const getAllRHSPeopleNames = () => {
  return commonPage.getTextForElements(peopleCardSelectors.rhsPeopleListSelector);
};

const getAllRHSReportsNames = async () => {
  await reportsCardSelectors.rhsReportListElement().waitForDisplayed();
  return commonPage.getTextForElements(reportsCardSelectors.rhsReportElementList);
};

const getAllRHSTaskNames = async () => {
  await tasksCardSelectors.rhsTaskListElement().waitForDisplayed();
  return commonPage.getTextForElements(tasksCardSelectors.rhsTaskListElementList);
};

const allContactsList = async () => {
  const parentCards = await rightPanelSelectors.childrenCards();

  return parentCards.map(async (parent) => ({
    heading: await parent.$('h3').getText(),
    contactNames: await parent.$$('.children h4 span').map(filter => filter.getText())
  }));
};

const editPlace = async (currentName, editedName) => {
  await selectLHSRowByText(currentName, true);
  await commonPage.accessEditOption();

  await commonEnketoPage.setInputValue('Name of this', editedName);
  await genericForm.submitForm();
};

const openFormWithWarning = async (formId) => {
  await commonPage.clickFastActionFAB({ actionId: formId });
  return modalPage.getModalDetails();
};

const openReport = async () => {
  await reportsCardSelectors.rhsReportListElement().waitForDisplayed();
  await reportsCardSelectors.rhsReportListElement().click();
};

const getContactCardTitle = async () => {
  await rightPanelSelectors.contactCardTitle().waitForDisplayed();
  return (await rightPanelSelectors.contactCardTitle()).getText();
};

const getContactInfoName = async () => {
  await contactCardSelectors.contactCardName().waitForDisplayed();
  return (await contactCardSelectors.contactCardName()).getText();
};

const getContactMedicID = async () => {
  await contactCardSelectors.contactMedicID().waitForDisplayed();
  return (await contactCardSelectors.contactMedicID()).getText();
};

const getContactDeceasedStatus = async () => {
  const deceasedStatus = await contactCardSelectors.contactDeceasedStatus();
  await deceasedStatus.waitForDisplayed();
  return await deceasedStatus.getText();
};

const getPregnancyCardInfo = async () => {
  await pregnancyCardSelectors.pregnancyCard().waitForDisplayed();
  return {
    weeksPregnant: await pregnancyCardSelectors.weeksPregnant().getText(),
    deliveryDate: await pregnancyCardSelectors.edd().getText(),
    risk: await pregnancyCardSelectors.highRisk().getText(),
    ancVisit: await pregnancyCardSelectors.nextANCVisit().getText(),
  };
};

const getDeathCardInfo = async () => {
  await deathCardSelectors.deathCard().waitForDisplayed();
  return {
    deathDate: await deathCardSelectors.deathDate().getText(),
    deathPlace: await deathCardSelectors.deathPlace().getText(),
  };
};

const getCurrentContactId = async () => {
  const currentUrl = await browser.getUrl();
  const contactBaseUrl = utils.getBaseUrl() + 'contacts/';
  if (!currentUrl.startsWith(contactBaseUrl)) {
    return;
  }

  return currentUrl.slice(contactBaseUrl.length);
};

const getContactListLoadingStatus = async () => {
  await leftPanelSelectors.contactListLoadingStatus().waitForDisplayed();
  return await leftPanelSelectors.contactListLoadingStatus().getText();
};

const getDisplayedContactsNames = async () => {
  const contacts = [];
  for (const row of await leftPanelSelectors.contentRows()) {
    contacts.push(await row.getText());
  }
  return contacts;
};

const getCurrentPersonEditFormValues = async (sexValue, roleValue) => {
  return {
    name: await commonEnketoPage.getInputValue('Full name'),
    shortName: await commonEnketoPage.getInputValue('Short name'),
    dateOfBirth: await commonEnketoPage.getInputValue('Age'),
    sex: await commonEnketoPage.isRadioButtonSelected('Sex', sexValue),
    role: await commonEnketoPage.isRadioButtonSelected('Role', roleValue),
    phone: await commonEnketoPage.getInputValue('Phone Number'),
    externalId: await commonEnketoPage.getInputValue('External ID'),
    notes: await commonEnketoPage.getTextareaValue('Notes'),
  };
};

const filterReportViewAll = async () => {
  const tabsContainer = $(`${RHS_REPORT_LIST_CARD} .action-header .table-filter`);
  await tabsContainer.scrollIntoView();
  await tabsContainer.$('*=View all').click();
};

const openFirstContact = async () => {
  const firstContact = leftPanelSelectors.firstContact();
  await firstContact.click();
};

const openPrimaryContactSearchDropdown = async () => {
  await editDistrictHospitalSelectors.primaryContactSearchDropdown().click();
};

const inputPrimaryContactSearchValue = async (searchQuery) => {
  await editDistrictHospitalSelectors.primaryContactSearchInput().waitForDisplayed();
  await editDistrictHospitalSelectors.primaryContactSearchInput().setValue(searchQuery);
  await editDistrictHospitalSelectors.primaryContactSearchFirstResult().waitForDisplayed();
};

const selectPrimaryContactSearchFirstResult = async () => {
  await editDistrictHospitalSelectors.primaryContactSearchFirstResult().click();
};


module.exports = {
  genericForm,
  leftPanelSelectors,
  rightPanelSelectors,
  contactCardSelectors,
  tasksCardSelectors,
  reportsCardSelectors,
  pregnancyCardSelectors,
  deathCardSelectors,
  inmunizationCardSelectors,
  selectLHSRowByText,
  selectRHSRowById,
  getReportFiltersText,
  getReportTaskFiltersText,
  getAllLHSContactsNames,
  addPerson,
  addPlace,
  getPrimaryContactName,
  getAllRHSPeopleNames,
  waitForContactLoaded,
  waitForContactUnloaded,
  editPerson,
  editPersonName,
  editPlace,
  getContactSummaryField,
  getAllRHSReportsNames,
  getAllRHSTaskNames,
  deletePerson,
  allContactsList,
  openReport,
  getContactCardTitle,
  getContactInfoName,
  getContactMedicID,
  getContactDeceasedStatus,
  getPregnancyCardInfo,
  getDeathCardInfo,
  openFormWithWarning,
  getContactListLoadingStatus,
  getCurrentContactId,
  getDisplayedContactsNames,
  getCurrentPersonEditFormValues,
  filterReportViewAll,
  openFirstContact,
  openPrimaryContactSearchDropdown,
  inputPrimaryContactSearchValue,
  selectPrimaryContactSearchFirstResult,
  openSortMenu,
  selectSortOrder,
};
