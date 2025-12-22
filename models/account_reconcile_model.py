from odoo import fields, models, Command, tools
from odoo.tools import SQL

import re
import logging
from collections import defaultdict
from dateutil.relativedelta import relativedelta
from datetime import datetime
import os

# Custom logger for reconciliation debugging
def log_reconciliation(message):
    return
    """Write reconciliation debug info to a separate log file"""
    log_file = "/var/log/odoo/odoo_reconciliation_debug.log"
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    try:
        with open(log_file, "a", encoding="utf-8") as f:
            f.write(f"[{timestamp}] {message}\n")
            f.flush()
    except Exception as e:
        pass  # Don't break reconciliation if logging fails

_logger = logging.getLogger(__name__)


class AccountReconcileModel(models.Model):
    _inherit = 'account.reconcile.model'

    ####################################################
    # RECONCILIATION PROCESS
    ####################################################

    def _apply_lines_for_bank_widget(self, residual_amount_currency, partner, st_line):
        """ Apply the reconciliation model lines to the statement line passed as parameter.

        :param residual_amount_currency:    The open balance of the statement line in the bank reconciliation widget
                                            expressed in the statement line currency.
        :param partner:                     The partner set on the wizard.
        :param st_line:                     The statement line processed by the bank reconciliation widget.
        :return:                            A list of python dictionaries (one per reconcile model line) representing
                                            the journal items to be created by the current reconcile model.
        """
        self.ensure_one()
        currency = st_line.foreign_currency_id or st_line.journal_id.currency_id or st_line.company_currency_id
        vals_list = []
        for line in self.line_ids:
            vals = line._apply_in_bank_widget(residual_amount_currency, partner, st_line)
            amount_currency = vals['amount_currency']

            if currency.is_zero(amount_currency):
                continue

            vals_list.append(vals)
            residual_amount_currency -= amount_currency

        return vals_list

    ####################################################
    # RECONCILIATION CRITERIA
    ####################################################

    def _apply_rules(self, st_line, partner):
        ''' Apply criteria to get candidates for all reconciliation models.

        This function is called in enterprise by the reconciliation widget to match
        the statement line with the available candidates (using the reconciliation models).

        :param st_line: The statement line to match.
        :param partner: The partner to consider.
        :return:        A dict mapping each statement line id with:
            * aml_ids:          A list of account.move.line ids.
            * model:            An account.reconcile.model record (optional).
            * status:           'reconciled' if the lines has been already reconciled, 'write_off' if the write-off
                                must be applied on the statement line.
            * auto_reconcile:   A flag indicating if the match is enough significant to auto reconcile the candidates.
        '''
        # Special handling for specific supplier transactions (negative amounts)
        # Automatically set partner based on keywords in payment_ref for supplier invoice matching
        if not partner and st_line.payment_ref:
            payment_ref_lower = st_line.payment_ref.lower()
            if 'alza' in payment_ref_lower:
                alza_partner = self.env['res.partner'].browse(21)
                if alza_partner.exists():
                    partner = alza_partner
                    log_reconciliation(f"Auto-assigned Alza partner (ID: 21) based on payment_ref containing 'alza' with negative amount")
            elif 'gamers outlet' in payment_ref_lower or 'gamersoutlet' in payment_ref_lower:
                gamers_partner = self.env['res.partner'].browse(1688)
                if gamers_partner.exists():
                    partner = gamers_partner
                    log_reconciliation(f"Auto-assigned GAMERS OUTLET partner (ID: 1688) based on payment_ref containing 'gamers outlet' with negative amount")
            elif 'smartstores' in payment_ref_lower or 'smart stores' in payment_ref_lower:
                smartstores_partner = self.env['res.partner'].browse(1691)
                if smartstores_partner.exists():
                    partner = smartstores_partner
                    log_reconciliation(f"Auto-assigned smartstores.sk partner (ID: 1691) based on payment_ref containing 'smartstores' with negative amount")
            elif 'westech' in payment_ref_lower:
                westech_partner = self.env['res.partner'].browse(4941)
                if westech_partner.exists():
                    partner = westech_partner
                    log_reconciliation(f"Auto-assigned WESTech partner (ID: 4941) based on payment_ref containing 'westech' with negative amount")
            elif 'tss group' in payment_ref_lower or 'tssgroup' in payment_ref_lower or 'tss-group' in payment_ref_lower:
                tss_partner = self.env['res.partner'].browse(1661)
                if tss_partner.exists():
                    partner = tss_partner
                    log_reconciliation(f"Auto-assigned TSS Group partner (ID: 1661) based on payment_ref containing 'tss group' with negative amount")
            elif 'slovak telekom' in payment_ref_lower or 'telekom' in payment_ref_lower:
                telekom_partner = self.env['res.partner'].browse(1662)
                if telekom_partner.exists():
                    partner = telekom_partner
                    log_reconciliation(f"Auto-assigned Slovak Telekom a.s. partner (ID: 1662) based on payment_ref containing 'telekom' with negative amount")
            elif 'acs spol' in payment_ref_lower or 'acs s.r.o' in payment_ref_lower or 'acs s r o' in payment_ref_lower:
                acs_partner = self.env['res.partner'].browse(1660)
                if acs_partner.exists():
                    partner = acs_partner
                    log_reconciliation(f"Auto-assigned ACS spol. s r.o partner (ID: 1660) based on payment_ref containing 'acs' with negative amount")
            elif 'upc broadband slovakia' in payment_ref_lower or 'upc' in payment_ref_lower:
                upc_partner = self.env['res.partner'].browse(1648)
                if upc_partner.exists():
                    partner = upc_partner
                    log_reconciliation(f"Auto-assigned UPC Broadband Slovakia partner (ID: 1648) based on payment_ref containing 'upc' with negative amount")
        
        log_reconciliation("=== RECONCILIATION PROCESS START ===")
        log_reconciliation(f"Statement Line ID: {st_line.id}, Amount: {st_line.amount}, Payment Ref: '{st_line.payment_ref}', Partner: {partner.name if partner else 'None'} (ID: {partner.id if partner else 'None'})")
        
        # Sort models: writeoff_suggestion models with text matching come first, then others
        def model_sort_key(model):
            # Prioritize writeoff models that have specific text matching
            if model.rule_type == 'writeoff_suggestion':
                if model.match_label or model.match_note:
                    return (0, model.sequence)  # Highest priority
                return (1, model.sequence)  # Second priority
            else:
                return (2, model.sequence)  # Lowest priority (invoice_matching, etc.)
        
        available_models = self.filtered(lambda m: m.rule_type != 'writeoff_button').sorted(key=model_sort_key)
        log_reconciliation(f"Available reconciliation models: {len(available_models)} - {[m.name for m in available_models]}")

        for rec_model in available_models:
            log_reconciliation(f"--- Checking model: '{rec_model.name}' (type: {rec_model.rule_type}) ---")

            if not rec_model._is_applicable_for(st_line, partner):
                log_reconciliation(f"Model '{rec_model.name}' is NOT applicable for this statement line")
                continue

            log_reconciliation(f"Model '{rec_model.name}' IS applicable for this statement line")
            if rec_model.rule_type == 'invoice_matching':
                rules_map = rec_model._get_invoice_matching_rules_map()
                log_reconciliation(f"Invoice matching rules: {list(rules_map.keys())}")
                for rule_index in sorted(rules_map.keys()):
                    for rule_method in rules_map[rule_index]:
                        log_reconciliation(f"Executing rule method: {rule_method.__name__}")
                        candidate_vals = rule_method(st_line, partner)
                        if not candidate_vals:
                            log_reconciliation(f"Rule method {rule_method.__name__} returned no candidates")
                            continue

                        log_reconciliation(f"Rule method {rule_method.__name__} found candidates: {candidate_vals}")
                        if candidate_vals.get('amls'):
                            res = rec_model._get_invoice_matching_amls_result(st_line, partner, candidate_vals)
                            if res:
                                # Check if this is a poor quality match (huge amount difference)
                                # If the difference is more than 50% of the statement line amount, skip this match
                                st_line_amount = abs(st_line.amount)
                                if res.get('amls'):
                                    # res['amls'] contains account.move.line recordset objects, not dicts
                                    total_aml_residual = sum(abs(aml.amount_residual) for aml in res['amls'])
                                    amount_diff = abs(st_line_amount - total_aml_residual)
                                    
                                    if st_line_amount > 0 and (amount_diff / st_line_amount) > 0.5:
                                        log_reconciliation(f"Skipping poor quality match from '{rec_model.name}': "
                                                         f"st_line amount {st_line_amount}, total_aml_residual {total_aml_residual}, "
                                                         f"diff {amount_diff} ({100*amount_diff/st_line_amount:.1f}%)")
                                        continue  # Skip this poor match and try other models
                                
                                log_reconciliation(f"Final result from model '{rec_model.name}': {res}")
                                return {
                                    **res,
                                    'model': rec_model,
                                }
                        else:
                            log_reconciliation(f"Returning candidate_vals directly: {candidate_vals}")
                            return {
                                **candidate_vals,
                                'model': rec_model,
                            }

            elif rec_model.rule_type == 'writeoff_suggestion':
                log_reconciliation(f"Returning writeoff suggestion for model '{rec_model.name}'")
                result = {
                    'model': rec_model,
                    'status': 'write_off',
                    'auto_reconcile': rec_model.auto_reconcile,
                }
                
                # Special handling for specific models - remove partner
                # Models: "Istina" (ID: 13), "Uroky" (ID: 19)
                if rec_model.name in ['Istina', 'Uroky'] or rec_model.id in [13, 19]:
                    result['partner'] = None
                    log_reconciliation(f"Removing partner for '{rec_model.name}' model")
                
                return result
        
        log_reconciliation("=== NO MATCHES FOUND - RECONCILIATION PROCESS END ===")
        return {}

    def _is_applicable_for(self, st_line, partner):
        """ Returns true iff this reconciliation model can be used to search for matches
        for the provided statement line and partner.
        """
        self.ensure_one()
        
        log_reconciliation(f"Checking applicability for model '{self.name}':")
        log_reconciliation(f"  - Journal check: model journals {[j.name for j in self.match_journal_ids]} vs st_line journal {st_line.move_id.journal_id.name}")
        log_reconciliation(f"  - Amount nature: {self.match_nature} vs st_line amount {st_line.amount}")
        log_reconciliation(f"  - Amount range: {self.match_amount} (min: {self.match_amount_min}, max: {self.match_amount_max}) vs abs amount {abs(st_line.amount)}")
        log_reconciliation(f"  - Partner check: match_partner={self.match_partner}, partner={partner.name if partner else 'None'}")
        log_reconciliation(f"  - Partner for matching: {partner.name if partner else 'Not set'}")
        
        # Hardcoded exclusion: "Transak dan" model should not match if "alza" is in the label
        if self.name == 'Transak dan' or self.id == 18:
            payment_ref_lower = (st_line.payment_ref or '').lower()
            if any(term in payment_ref_lower for term in ['alza', 'microsoft', 'cashback']):
                log_reconciliation(f"  - EXCLUDED: 'Transak dan' model skipped because 'alza' or 'microsoft' found in label")
                return False

        # Filter on journals, amount nature, amount and partners
        # All the conditions defined in this block are non-match conditions.
        # For 'between' checks with negative ranges, use signed amount instead of abs
        amount_to_check = st_line.amount if (self.match_amount == 'between' and self.match_amount_min < 0) else abs(st_line.amount)
        
        if ((self.match_journal_ids and st_line.move_id.journal_id not in self.match_journal_ids)
            or (self.match_nature == 'amount_received' and st_line.amount < 0)
            or (self.match_nature == 'amount_paid' and st_line.amount > 0)
            or (self.match_amount == 'lower' and abs(st_line.amount) >= self.match_amount_max)
            or (self.match_amount == 'greater' and abs(st_line.amount) <= self.match_amount_min)
            or (self.match_amount == 'between' and (amount_to_check > self.match_amount_max or amount_to_check < self.match_amount_min))
            or (self.match_partner and not partner)
            or (self.match_partner and self.match_partner_ids and partner not in self.match_partner_ids)
            or (self.match_partner and self.match_partner_category_ids and not (partner.category_id & self.match_partner_category_ids))
        ):
            log_reconciliation(f"  - FAILED basic criteria checks")
            return False

        # Filter on label, note and transaction_type with improved text matching
        for record, rule_field, record_field in [(st_line, 'label', 'payment_ref'), (st_line.move_id, 'note', 'narration'), (st_line, 'transaction_type', 'transaction_type')]:
            rule_term = (self['match_' + rule_field + '_param'] or '').strip().lower()
            record_term = (record[record_field] or '').strip().lower()
            
            # Log the matching attempt for debugging
            if rule_term:
                log_reconciliation(f"  - Text matching: field={rule_field}, rule_term='{rule_term}', record_term='{record_term[:100]}...', match_type={self['match_' + rule_field]}")
            
            # Skip empty rules
            if not rule_term:
                continue

            # This defines non-match conditions with improved robustness
            try:
                if ((self['match_' + rule_field] == 'contains' and rule_term not in record_term)
                    or (self['match_' + rule_field] == 'not_contains' and rule_term in record_term)
                    or (self['match_' + rule_field] == 'match_regex' and not re.match(rule_term, record_term, re.IGNORECASE))
                ):
                    log_reconciliation(f"  - FAILED text matching for {rule_field}")
                    return False
            except re.error:
                # If regex is invalid, fall back to simple string matching
                if ((self['match_' + rule_field] == 'contains' and rule_term not in record_term)
                    or (self['match_' + rule_field] == 'not_contains' and rule_term in record_term)
                    or (self['match_' + rule_field] == 'match_regex' and rule_term != record_term)
                ):
                    log_reconciliation(f"  - FAILED text matching for {rule_field} (regex error fallback)")
                    return False

        return True

    def _get_invoice_matching_amls_domain(self, st_line, partner):
        # Get the basic domain from the statement line
        aml_domain = st_line._get_default_amls_matching_domain()

        # Ensure we only match with 311000 (Customers) and 321000 (Suppliers) accounts
        # Filter based on account codes
        allowed_accounts = ('311000', '321000')  # Only allow these account codes
        aml_domain.append(('account_id.code', 'in', allowed_accounts))

        # Match the correct balance direction
        if st_line.amount > 0.0:
            aml_domain.append(('balance', '>', 0.0))
        else:
            aml_domain.append(('balance', '<', 0.0))

        log_reconciliation(f"Matching only with accounts: {allowed_accounts}")

        currency = st_line.foreign_currency_id or st_line.currency_id
        if self.match_same_currency:
            aml_domain.append(('currency_id', '=', currency.id))

        if partner:
            aml_domain.append(('partner_id', '=', partner.id))

        if self.past_months_limit:
            date_limit = fields.Date.context_today(self) - relativedelta(months=self.past_months_limit)
            aml_domain.append(('date', '>=', fields.Date.to_string(date_limit)))

        return aml_domain

    def _get_st_line_text_values_for_matching(self, st_line):
        """ Collect the strings that could be used on the statement line to perform some matching.
        :param st_line: The current statement line.
        :return: A list of strings.
        """
        self.ensure_one()
        allowed_fields = []
        if self.match_text_location_label:
            allowed_fields.append('payment_ref')
        if self.match_text_location_note:
            allowed_fields.append('narration')
        if self.match_text_location_reference:
            allowed_fields.append('ref')
        return st_line._get_st_line_strings_for_matching(allowed_fields=allowed_fields)

    def _get_invoice_matching_st_line_tokens(self, st_line):
        """ Parse the textual information from the statement line passed as parameter
        in order to extract from it the meaningful information in order to perform the matching.

        :param st_line: A statement line.
        :return:    A tuple of list of tokens, each one being a string.
                    The first element is a list of tokens you may match on numerical information.
                    The second element is a list of tokens you may match exactly.
                    The third element is a list of text tokens for additional context.
        """
        st_line_text_values = self._get_st_line_text_values_for_matching(st_line)
        
        # We'll focus on extracting FAK and VS patterns with highest priority
        numerical_tokens = []
        exact_tokens = set()  # preventing duplicates
        text_tokens = []
        reference_patterns = []  # High priority reference patterns (FAK, VS)
        
        # Regular expression patterns - prioritize invoice reference matching
        fak_pattern = re.compile(r'(FAK/\d{4}/\d{4,8})', re.IGNORECASE)
        vs_pattern1 = re.compile(r'/VS(\d{6,9})/', re.IGNORECASE)
        vs_pattern2 = re.compile(r'VS[^\d]*(\d{6,9})', re.IGNORECASE)
        
        # Combine all text values for efficient pattern matching
        all_text = ' '.join(value for value in st_line_text_values if value)
        
        # First, extract FAK/YYYY/NNNNN patterns (highest priority)
        fak_matches = fak_pattern.findall(all_text)
        if fak_matches:
            log_reconciliation(f"Found FAK references in line {st_line.id}: {fak_matches}")
            reference_patterns.extend(fak_matches)
            exact_tokens.update(fak_matches)
            
            # Special handling - also add stripped FAK numbers without leading zeros
            for fak in fak_matches:
                parts = fak.split('/')
                if len(parts) == 3:
                    # Convert FAK/2025/00416 to FAK/2025/416 for additional matching
                    clean_num = parts[2].lstrip('0')
                    if clean_num != parts[2]:
                        clean_fak = f"{parts[0]}/{parts[1]}/{clean_num}"
                        reference_patterns.append(clean_fak)
                        exact_tokens.add(clean_fak)
        
        # Second, extract VS patterns
        vs_matches1 = vs_pattern1.findall(all_text)  # /VS123456/
        vs_matches2 = vs_pattern2.findall(all_text)  # VS123456
        vs_matches = list(set(vs_matches1 + vs_matches2))
        
        if vs_matches:
            log_reconciliation(f"Found VS references in line {st_line.id}: {vs_matches}")
            reference_patterns.extend(vs_matches)
            exact_tokens.update(vs_matches)
            # Also add VS prefix versions
            for vs in vs_matches:
                exact_tokens.add(f"VS{vs}")
                reference_patterns.append(f"VS{vs}")
                
        # Process regular tokens only if we didn't find specific references
        for text_value in st_line_text_values:
            if not text_value or not text_value.strip():
                continue
                
            text_value = text_value.strip()
            split_text = text_value.split()
            
            # Exact tokens - include full text and individual tokens
            if text_value:
                exact_tokens.add(text_value)
            
            exact_tokens.update(
                token.strip() for token in split_text
                if token and token.strip()
            )
            
            # Text tokens - clean and normalize
            tokens = []
            for token in split_text:
                if not token:
                    continue
                # Remove punctuation but keep alphanumeric chars and spaces
                cleaned_token = ''.join(x for x in token if re.match(r'[0-9a-zA-ZàáâãäåæçèéêëìíîïðñòóôõöøùúûüýþÿĀāĂăĄąĆćĈĉĊċČčĎďĐđĒēĔĕĖėĘęĚěĜĝĞğĠġĢģĤĥĦħĨĩĪīĬĭĮįİıĲĳĴĵĶķĸĹĺĻļĽľĿŀŁłŃńŅņŇňŉŊŋŌōŎŏŐőŒœŔŕŖŗŘřŚśŜŝŞşŠšŢţŤťŦŧŨũŪūŬŭŮůŰűŲųŴŵŶŷŸŹźŻżŽž\s\-/]', x))
                if cleaned_token:
                    tokens.append(cleaned_token.strip())

            # Process all tokens
            for token in tokens:
                if not token:
                    continue
                    
                text_tokens.append(token)

                # Extract numerical parts for numerical matching
                formatted_token = ''.join(x for x in token if x.isdecimal())
                if formatted_token:
                    numerical_tokens.append(formatted_token)

        # Remove empty tokens and duplicates while preserving order for numerical tokens
        numerical_tokens = list(dict.fromkeys(token for token in numerical_tokens if token))
        exact_tokens = {token for token in exact_tokens if token and token.strip()}
        text_tokens = list(dict.fromkeys(token for token in text_tokens if token))
        
        # Create a list with references patterns first, then other tokens
        # This ensures FAK and VS patterns are checked first during matching
        exact_token_list = reference_patterns + [token for token in exact_tokens if token not in reference_patterns]

        return numerical_tokens, exact_token_list, text_tokens

    def _get_invoice_matching_amls_candidates(self, st_line, partner):
        """ Returns the match candidates for the 'invoice_matching' rule, with respect to the provided parameters.

        :param st_line: A statement line.
        :param partner: The partner associated to the statement line.
        """
        def get_order_by_clause(prefix=SQL()):
            direction = SQL(' DESC') if self.matching_order == 'new_first' else SQL(' ASC')
            return SQL(", ").join(
                SQL("%s%s%s", prefix, SQL(field), direction)
                for field in ('date_maturity', 'date', 'id')
            )

        assert self.rule_type == 'invoice_matching'
        log_reconciliation(f"Starting _get_invoice_matching_amls_candidates for partner {partner.name if partner else 'None'}")
        log_reconciliation(f"Model text matching settings: label={self.match_text_location_label}, note={self.match_text_location_note}, reference={self.match_text_location_reference}")
        
        self.env['account.move'].flush_model()
        self.env['account.move.line'].flush_model()

        aml_domain = self._get_invoice_matching_amls_domain(st_line, partner)
        log_reconciliation(f"AML domain: {aml_domain}")
        
        query = self.env['account.move.line']._where_calc(aml_domain)
        tables = query.from_clause
        where_clause = query.where_clause or SQL("TRUE")

        aml_cte = SQL()
        sub_queries: list[SQL] = []
        numerical_tokens, exact_tokens, _text_tokens = self._get_invoice_matching_st_line_tokens(st_line)
        if numerical_tokens or exact_tokens:
            aml_cte = SQL('''
                WITH aml_cte AS (
                    SELECT
                        account_move_line.id as account_move_line_id,
                        account_move_line.date as account_move_line_date,
                        account_move_line.date_maturity as account_move_line_date_maturity,
                        account_move_line.name as account_move_line_name,
                        account_move_line__move_id.name as account_move_line__move_id_name,
                        account_move_line__move_id.ref as account_move_line__move_id_ref
                    FROM %s
                    JOIN account_move account_move_line__move_id ON account_move_line__move_id.id = account_move_line.move_id
                    WHERE %s
                )
            ''', tables, where_clause)
        if numerical_tokens:
            for table_alias, field in (
                ('account_move_line', 'name'),
                ('account_move_line__move_id', 'name'),
                ('account_move_line__move_id', 'ref'),
            ):
                sub_queries.append(SQL(r'''
                    SELECT
                        account_move_line_id as id,
                        account_move_line_date as date,
                        account_move_line_date_maturity as date_maturity,
                        UPPER(UNNEST(
                            REGEXP_SPLIT_TO_ARRAY(
                                SUBSTRING(
                                    REGEXP_REPLACE(%(field)s, '[^0-9\s]', '', 'g'),
                                    '\S(?:.*\S)*'
                                ),
                                '\s+'
                            )
                        )) AS token
                    FROM aml_cte
                    WHERE %(field)s IS NOT NULL
                ''', field=SQL("%s_%s", SQL(table_alias), SQL(field))))
        if exact_tokens:
            for table_alias, field in (
                ('account_move_line', 'name'),
                ('account_move_line__move_id', 'name'),
                ('account_move_line__move_id', 'ref'),
            ):
                sub_queries.append(SQL('''
                    SELECT
                        account_move_line_id as id,
                        account_move_line_date as date,
                        account_move_line_date_maturity as date_maturity,
                        UPPER(%(field)s) AS token
                    FROM aml_cte
                    WHERE %(field)s != ''
                ''', field=SQL("%s_%s", SQL(table_alias), SQL(field))))
        if sub_queries:
            order_by = get_order_by_clause(prefix=SQL('sub.'))
            # Make token matching case-insensitive and handle null values robustly
            search_tokens = tuple(token.upper().strip() for token in numerical_tokens + exact_tokens if token and token.strip())
            log_reconciliation(f"Search tokens for SQL query: {search_tokens}")
            
            if search_tokens:  # Only execute if we have valid tokens to search for
                log_reconciliation(f"Executing token-based SQL query with {len(sub_queries)} sub-queries")
                
                # DEBUG: Show what tokens exist in the database for this partner
                debug_tokens = [r for r in self.env.execute_query(SQL(
                    '''
                        %s
                        SELECT DISTINCT
                            sub.token
                        FROM (%s) AS sub
                        WHERE sub.token IS NOT NULL 
                            AND TRIM(sub.token) != ''
                        ORDER BY sub.token
                        LIMIT 20
                    ''',
                    aml_cte,
                    SQL(" UNION ALL ").join(sub_queries),
                ))]
                log_reconciliation(f"Available tokens in database (first 20): {[t[0] for t in debug_tokens]}")
                
                candidate_ids = [r[0] for r in self.env.execute_query(SQL(
                    '''
                        %s
                        SELECT
                            sub.id,
                            COUNT(*) AS nb_match
                        FROM (%s) AS sub
                        WHERE sub.token IS NOT NULL 
                            AND TRIM(sub.token) != ''
                            AND sub.token IN %s
                        GROUP BY sub.date_maturity, sub.date, sub.id
                        HAVING COUNT(*) > 0
                        ORDER BY nb_match DESC, %s
                    ''',
                    aml_cte,
                    SQL(" UNION ALL ").join(sub_queries),
                    search_tokens,
                    order_by,
                ))]
                log_reconciliation(f"Token-based query found {len(candidate_ids)} candidates: {candidate_ids}")
            else:
                log_reconciliation("No valid search tokens found, skipping token-based query")
                candidate_ids = []
            if candidate_ids:
                return {
                    'allow_auto_reconcile': True,
                    'amls': self.env['account.move.line'].browse(candidate_ids),
                }
            elif self.match_text_location_label or self.match_text_location_note or self.match_text_location_reference:
                # In the case any of the Label, Note or Reference matching rule has been toggled, and the query didn't return
                # any candidates, the model should not try to mount another aml instead.
                # MODIFIED: Allow fallback to amount/partner matching for better reconciliation coverage
                log_reconciliation(f"Text matching enabled (label:{self.match_text_location_label}, note:{self.match_text_location_note}, ref:{self.match_text_location_reference}) but no token matches found - ALLOWING fallback matching")
                # Don't return early - allow fallback matching to proceed

        # Fallback to amount-based matching when no text matches or no partner
        log_reconciliation(f"Checking fallback amount-based matching (partner: {partner.name if partner else 'None'})")
        if not partner:
            log_reconciliation("No partner found, using amount-based matching")
            st_line_currency = st_line.foreign_currency_id or st_line.journal_id.currency_id or st_line.company_currency_id
            if st_line_currency == self.company_id.currency_id:
                aml_amount_field = SQL('amount_residual')
            else:
                aml_amount_field = SQL('amount_residual_currency')

            order_by = get_order_by_clause(prefix=SQL('account_move_line.'))
            
            # Try exact amount match first
            log_reconciliation(f"Searching for amount match: {abs(st_line.amount_residual)} in currency {st_line_currency.name}")
            rows = self.env.execute_query(SQL(
                '''
                    SELECT account_move_line.id, ABS(account_move_line.%s) as abs_amount
                    FROM %s
                    WHERE
                        %s
                        AND account_move_line.currency_id = %s
                        AND ROUND(ABS(account_move_line.%s), %s) = ROUND(%s, %s)
                    ORDER BY %s
                ''',
                aml_amount_field,
                tables,
                where_clause,
                st_line_currency.id,
                aml_amount_field,
                st_line_currency.decimal_places,
                abs(st_line.amount_residual),
                st_line_currency.decimal_places,
                order_by,
            ))
            amls = self.env['account.move.line'].browse([row[0] for row in rows])
            log_reconciliation(f"Amount-based query found {len(amls)} candidates: {[aml.id for aml in amls]}")
        else:
            # When partner is available, use domain-based search with better ordering
            log_reconciliation("Partner available, using domain-based search")
            amls = self.env['account.move.line'].search(aml_domain, order=get_order_by_clause().code)
            log_reconciliation(f"Domain-based search found {len(amls)} candidates: {[aml.id for aml in amls]}")
            
            # DEBUG: Show details of found candidates for better understanding
            if amls:
                for aml in amls[:5]:  # Show first 5 candidates
                    log_reconciliation(f"  Candidate AML {aml.id}: name='{aml.name}', move_name='{aml.move_id.name}', ref='{aml.move_id.ref}', amount_residual={aml.amount_residual}")

        if amls:
            # Only proceed with auto-reconciliation if we have a partner
            if not partner:
                log_reconciliation("No partner available - disabling auto-reconcile for safety")
                return {
                    'allow_auto_reconcile': False,
                    'amls': amls,
                }

            # First, check for invoice reference number matches in st_line.payment_ref or narration
            has_invoice_ref_match = False
            invoice_ref_pattern = re.compile(r'([A-Z]{2,5}/\d{4}/\d{4,8})', re.IGNORECASE)
            
            # Extract invoice references from statement line text
            payment_ref_matches = invoice_ref_pattern.findall(st_line.payment_ref or '')
            narration_matches = invoice_ref_pattern.findall(st_line.narration or '')
            
            # Extract unique invoice reference patterns
            st_line_invoice_refs = list(set(payment_ref_matches + narration_matches))
            
            # Look for matches in AML move references or names
            invoice_ref_matches = []
            
            if st_line_invoice_refs:
                log_reconciliation(f"Found invoice references in statement line: {st_line_invoice_refs}")
                for aml in amls:
                    if aml.partner_id != partner:
                        log_reconciliation(f"  Skipping AML {aml.id} - partner mismatch: {aml.partner_id.name} vs {partner.name}")
                        continue
                    
                    # Check move references and names
                    move_ref = aml.move_id.ref or ''
                    move_name = aml.move_id.name or ''
                    
                    for ref in st_line_invoice_refs:
                        if ref in move_ref or ref in move_name:
                            invoice_ref_matches.append(aml)
                            log_reconciliation(f"  Found invoice ref match: AML {aml.id}, reference '{ref}' in move ref/name: '{move_ref}'/''{move_name}'")
                            break
            
            # If we found invoice reference matches, prioritize those
            if invoice_ref_matches:
                log_reconciliation(f"Using invoice reference matches: {len(invoice_ref_matches)} found")
                has_invoice_ref_match = True
                amls = self.env['account.move.line'].browse([aml.id for aml in invoice_ref_matches])
                chosen = invoice_ref_matches[0] if invoice_ref_matches else None
            else:
                # Fall back to amount-based matching with higher tolerance (5%)
                log_reconciliation(f"No invoice reference matches found, falling back to amount matching")
                st_line_amount = abs(st_line.amount)
                tolerance = 0.0001  # 0.01% tolerance (increased from 2%)
                perfect_matches = []

                for aml in amls:
                    if aml.partner_id != partner:
                        log_reconciliation(f"  Skipping AML {aml.id} - partner mismatch: {aml.partner_id.name} vs {partner.name}")
                        continue

                    aml_amount = abs(aml.amount_residual)
                    diff_percentage = abs(aml_amount - st_line_amount) / st_line_amount if st_line_amount else 1.0
                    if diff_percentage <= tolerance:
                        perfect_matches.append(aml)
                        log_reconciliation(
                            f"  Perfect match within {tolerance*100}% tolerance: AML {aml.id}, amount {aml_amount} vs {st_line_amount}, diff: {diff_percentage:.1%}"
                        )

                if perfect_matches:
                    # Sort primarily by closeness to payment amount,
                    # secondarily by oldest date (ascending)
                    sorted_matches = sorted(
                        perfect_matches,
                        key=lambda a: (
                            abs(abs(a.amount_residual) - st_line_amount),
                            a.date_maturity or a.date or fields.Date.today()
                        )
                    )
                    chosen = sorted_matches[0]
                    if len(perfect_matches) > 1:
                        log_reconciliation(
                            f"Multiple perfect matches found ({len(perfect_matches)}); "
                            f"choosing AML {chosen.id} with residual {abs(chosen.amount_residual)} "
                            f"(closest to {st_line_amount}, oldest date {chosen.date_maturity or chosen.date})"
                        )
                    amls = self.env['account.move.line'].browse([chosen.id])

            has_partner = bool(partner)
            # Initialize variables to ensure they always exist
            chosen = chosen if 'chosen' in locals() else None
            has_invoice_ref_match = has_invoice_ref_match if 'has_invoice_ref_match' in locals() else False
            perfect_matches = perfect_matches if 'perfect_matches' in locals() else []
            
            # Auto-reconcile if we have an invoice reference match or a close amount match
            allow_auto_reconcile = (bool(chosen) or has_invoice_ref_match) and has_partner and self.auto_reconcile
            log_reconciliation(
                f"Returning {len(amls)} candidates, perfect matches: {len(perfect_matches)}, "
                f"auto_reconcile: {allow_auto_reconcile}"
            )

            return {
                'allow_auto_reconcile': allow_auto_reconcile,
                'amls': amls,
            }
 



    def _get_invoice_matching_rules_map(self):
        """ Get a mapping <priority_order, rule> that could be overridden in others modules.

        :return: a mapping <priority_order, rule> where:
            * priority_order:   Defines in which order the rules will be evaluated, the lowest comes first.
                                This is extremely important since the algorithm stops when a rule returns some candidates.
            * rule:             Method taking <st_line, partner> as parameters and returning the candidates journal items found.
        """
        rules_map = defaultdict(list)
        
        # First try to match based on invoice reference patterns
        rules_map[5].append(self._get_invoice_ref_matching_candidates)
        
        # Then fall back to regular matching
        rules_map[10].append(self._get_invoice_matching_amls_candidates)
        return rules_map
        
    def _get_invoice_ref_matching_candidates(self, st_line, partner):
        """Try to match statement lines with invoices based on reference patterns like FAK/YYYY/NNNNN,
        or variable_code (like 202500403 or VS202500403)
        
        :param st_line: A statement line.
        :param partner: The partner to consider.
        :return: A dict containing the candidates.
        """
        from odoo.tools import html2plaintext
        
        # We'll try to match even without a partner if we find specific references
        partner_required = partner is not None
        if not partner:
            log_reconciliation("No partner for reference matching - will check for FAK/VS references only")
        
        # Regular expression patterns for FAK and VS references
        fak_pattern = re.compile(r'(FAK/\d{4}/\d{4,8})', re.IGNORECASE)
        vs_pattern1 = re.compile(r'/VS(\d{6,9})/', re.IGNORECASE)
        vs_pattern2 = re.compile(r'VS[^\d]*(\d{6,9})', re.IGNORECASE)  # VS followed by numbers
        
        # Focus primarily on payment_ref field as it's most likely to contain the references
        payment_ref = st_line.payment_ref or ''
        narration = html2plaintext(st_line.narration or '')
        
        log_reconciliation(f"Checking line {st_line.id} with payment_ref: '{payment_ref}'")
        
        # Extract all possible references
        fak_matches = fak_pattern.findall(payment_ref)
        vs_matches1 = vs_pattern1.findall(payment_ref)
        vs_matches2 = vs_pattern2.findall(payment_ref) 
        vs_matches = list(set(vs_matches1 + vs_matches2))  # Combine and deduplicate
        
        # If no matches in payment_ref, check narration as fallback
        if not (fak_matches or vs_matches):
            fak_matches = fak_pattern.findall(narration)
            vs_matches1 = vs_pattern1.findall(narration)
            vs_matches2 = vs_pattern2.findall(narration)
            vs_matches = list(set(vs_matches1 + vs_matches2))  # Combine and deduplicate
        
        # Create a list of all references to search for
        all_refs = fak_matches + vs_matches + ['VS' + vs for vs in vs_matches]
        
        # For FAK references, also add versions without leading zeros
        for fak in fak_matches:
            parts = fak.split('/')
            if len(parts) == 3:
                # Convert FAK/2025/00416 to FAK/2025/416 for additional matching
                clean_num = parts[2].lstrip('0')
                if clean_num != parts[2]:
                    all_refs.append(f"{parts[0]}/{parts[1]}/{clean_num}")
        
        # Log all found references for debugging
        if all_refs:
            log_reconciliation(f"Found reference patterns in statement line {st_line.id}: {all_refs}")
        
        # If no reference patterns found, skip this matching method
        if not all_refs:
            return {}
            
        log_reconciliation(f"Found references in statement line: {all_refs}")
        
        # Get all partner's open invoices
        aml_domain = self._get_invoice_matching_amls_domain(st_line, partner)
        amls = self.env['account.move.line'].search(aml_domain)
        
        # Look for matches in move references or names
        ref_matches = []
        
        for aml in amls:
            # Check move references and names
            move_ref = aml.move_id.ref or ''
            move_name = aml.move_id.name or ''
            
            for ref in all_refs:
                if ref in move_ref or ref in move_name:
                    ref_matches.append(aml)
                    log_reconciliation(f"Found reference match: AML {aml.id}, reference '{ref}' in move ref/name: '{move_ref}'/''{move_name}'")
                    break
                    
        if ref_matches:
            log_reconciliation(f"Reference matching found {len(ref_matches)} matches with zero amount tolerance")
            return {
                'allow_auto_reconcile': True,
                'amls': self.env['account.move.line'].browse([aml.id for aml in ref_matches]),
            }
            
        return {}

    def _get_partner_from_mapping(self, st_line):
        """Find partner with mapping defined on model.

        For invoice matching rules, matches the statement line against each
        regex defined in partner mapping, and returns the partner corresponding
        to the first one matching.

        :param st_line (Model<account.bank.statement.line>):
            The statement line that needs a partner to be found
        :return Model<res.partner>:
            The partner found from the mapping. Can be empty an empty recordset
            if there was nothing found from the mapping or if the function is
            not applicable.
        """
        self.ensure_one()

        if self.rule_type not in ('invoice_matching', 'writeoff_suggestion'):
            return self.env['res.partner']

        for partner_mapping in self.partner_mapping_line_ids:
            match_payment_ref = True
            if partner_mapping.payment_ref_regex:
                match_payment_ref = re.match(partner_mapping.payment_ref_regex, st_line.payment_ref) if st_line.payment_ref else False

            match_narration = True
            if partner_mapping.narration_regex:
                match_narration = re.match(
                    partner_mapping.narration_regex,
                    tools.html2plaintext(st_line.narration or '').rstrip(),
                    flags=re.DOTALL, # Ignore '/n' set by online sync.
                )

            if match_payment_ref and match_narration:
                return partner_mapping.partner_id
        return self.env['res.partner']

    def _get_invoice_matching_amls_result(self, st_line, partner, candidate_vals):
        def _create_result_dict(amls_values_list, status):
            if 'rejected' in status:
                return

            result = {'amls': self.env['account.move.line']}
            for aml_values in amls_values_list:
                result['amls'] |= aml_values['aml']

            if 'allow_write_off' in status and self.line_ids:
                result['status'] = 'write_off'

            # If allow_auto_reconcile is in status and the candidate is marked for auto reconciliation,
            # set auto_reconcile to True in the result - self.auto_reconcile check is already handled
            # in the allow_auto_reconcile setting
            if 'allow_auto_reconcile' in status and candidate_vals.get('allow_auto_reconcile'):
                result['auto_reconcile'] = True

            return result

        st_line_currency = st_line.foreign_currency_id or st_line.currency_id
        st_line_amount = st_line._prepare_move_line_default_vals()[1]['amount_currency']
        sign = 1 if st_line_amount > 0.0 else -1

        amls = candidate_vals['amls']
        amls_values_list = []
        amls_with_epd_values_list = []
        same_currency_mode = amls.currency_id == st_line_currency
        for aml in amls:
            aml_values = {
                'aml': aml,
                'amount_residual': aml.amount_residual,
                'amount_residual_currency': aml.amount_residual_currency,
            }

            amls_values_list.append(aml_values)

            # Manage the early payment discount.
            if aml.move_id.invoice_payment_term_id:
                last_discount_date = aml.move_id.invoice_payment_term_id._get_last_discount_date(aml.move_id.date)
            else:
                last_discount_date = False
            if same_currency_mode \
                    and aml.move_id.move_type in ('out_invoice', 'out_receipt', 'in_invoice', 'in_receipt') \
                    and not aml.matched_debit_ids \
                    and not aml.matched_credit_ids \
                    and last_discount_date \
                    and st_line.date <= last_discount_date:

                rate = abs(aml.amount_currency) / abs(aml.balance) if aml.balance else 1.0
                amls_with_epd_values_list.append({
                    **aml_values,
                    'amount_residual': st_line.company_currency_id.round(aml.discount_amount_currency / rate),
                    'amount_residual_currency': aml.discount_amount_currency,
                })
            else:
                amls_with_epd_values_list.append(aml_values)

        def match_batch_amls(amls_values_list):
            if not same_currency_mode:
                return None, []

            kepts_amls_values_list = []
            sum_amount_residual_currency = 0.0
            for aml_values in amls_values_list:

                if st_line_currency.compare_amounts(st_line_amount, -aml_values['amount_residual_currency']) == 0:
                    # Special case: the amounts are the same, submit the line directly.
                    return 'perfect', [aml_values]

                if st_line_currency.compare_amounts(sign * (st_line_amount + sum_amount_residual_currency), 0.0) > 0:
                    # Here, we still have room for other candidates ; so we add the current one to the list we keep.
                    # Then, we continue iterating, even if there is no room anymore, just in case one of the following candidates
                    # is an exact match, which would then be preferred on the current candidates.
                    kepts_amls_values_list.append(aml_values)
                    sum_amount_residual_currency += aml_values['amount_residual_currency']

            if st_line_currency.is_zero(sign * (st_line_amount + sum_amount_residual_currency)):
                return 'perfect', kepts_amls_values_list
            elif kepts_amls_values_list:
                return 'partial', kepts_amls_values_list
            else:
                return None, []

        # Try to match a batch with the early payment feature. Only a perfect match is allowed.
        match_type, kepts_amls_values_list = match_batch_amls(amls_with_epd_values_list)
        if match_type != 'perfect':
            kepts_amls_values_list = []

        # Try to match the amls having the same currency as the statement line.
        if not kepts_amls_values_list:
            _match_type, kepts_amls_values_list = match_batch_amls(amls_values_list)

        # Try to match the whole candidates.
        if not kepts_amls_values_list:
            kepts_amls_values_list = amls_values_list

        # Try to match the amls having the same currency as the statement line.
        if kepts_amls_values_list:
            status = self._check_rule_propositions(st_line, kepts_amls_values_list)
            result = _create_result_dict(kepts_amls_values_list, status)
            if result:
                return result

    def _check_rule_propositions(self, st_line, amls_values_list):
        """ Check restrictions that can't be handled for each move.line separately.
        Note: Only used by models having a type equals to 'invoice_matching'.
        :param st_line:             The statement line.
        :param amls_values_list:    The candidates account.move.line as a list of dict:
            * aml:                          The record.
            * amount_residual:              The amount residual to consider.
            * amount_residual_currency:     The amount residual in foreign currency to consider.
        :return: A string representing what to do with the candidates:
            * rejected:             Reject candidates.
            * allow_write_off:      Allow to generate the write-off from the reconcile model lines if specified.
            * allow_auto_reconcile: Allow to automatically reconcile entries if 'auto_validate' is enabled.
        """
        self.ensure_one()
        
        # First check for exact reference matches - bypass amount tolerance check completely
        # This special logic focuses on FAK and VS patterns with zero tolerance
        from odoo.tools import html2plaintext
        
        # Simplified approach - focus directly on the payment_ref field
        payment_ref = st_line.payment_ref or ''
        narration = html2plaintext(st_line.narration or '')
        all_text = payment_ref + ' ' + narration
        
        # Regular expression patterns for FAK and VS references
        fak_pattern = re.compile(r'(FAK/\d{4}/\d{4,8})', re.IGNORECASE)
        vs_pattern1 = re.compile(r'/VS(\d{6,9})/', re.IGNORECASE)
        vs_pattern2 = re.compile(r'VS[^\d]*(\d{6,9})', re.IGNORECASE)  # VS followed by numbers
        
        # Extract references
        fak_matches = fak_pattern.findall(all_text)
        vs_matches1 = vs_pattern1.findall(all_text)
        vs_matches2 = vs_pattern2.findall(all_text)
        vs_matches = list(set(vs_matches1 + vs_matches2))  # Combine and deduplicate
        
        # Log what we found
        if fak_matches:
            log_reconciliation(f"Found FAK references in statement line {st_line.id}: {fak_matches}")
        if vs_matches:
            log_reconciliation(f"Found VS references in statement line {st_line.id}: {vs_matches}")
        
        if fak_matches or vs_matches:
            log_reconciliation(f"Found reference patterns: FAK={fak_matches}, VS={vs_matches}")
            
            for aml_values in amls_values_list:
                aml = aml_values['aml']
                move_ref = aml.move_id.ref or ''
                move_name = aml.move_id.name or ''
                move_text = move_ref + ' ' + move_name
                
                # Check for FAK reference matches
                for ref in fak_matches:
                    if ref in move_text:
                        log_reconciliation(f"Exact FAK reference match ({ref}) found in {move_text} - auto-reconciling REGARDLESS of amount")
                        return {'allow_auto_reconcile'}
                
                # Check for VS reference matches
                for ref in vs_matches:
                    if ref in move_text:
                        log_reconciliation(f"Exact VS reference match ({ref}) found in {move_text} - auto-reconciling REGARDLESS of amount")
                        return {'allow_auto_reconcile'}
        
        # If no reference match was found, continue with normal tolerance checking
        if not self.allow_payment_tolerance:
            return {'allow_write_off', 'allow_auto_reconcile'}

        st_line_currency = st_line.foreign_currency_id or st_line.currency_id
        st_line_amount_curr = st_line._prepare_move_line_default_vals()[1]['amount_currency']
        amls_amount_curr = sum(
            st_line._prepare_counterpart_amounts_using_st_line_rate(
                aml_values['aml'].currency_id,
                aml_values['amount_residual'],
                aml_values['amount_residual_currency'],
            )['amount_currency']
            for aml_values in amls_values_list
        )
        sign = 1 if st_line_amount_curr > 0.0 else -1
        amount_curr_after_rec = st_line_currency.round(
            sign * (amls_amount_curr + st_line_amount_curr)
        )

        # Check if amounts match exactly or within tolerance
        if st_line_currency.is_zero(amount_curr_after_rec):
            return {'allow_auto_reconcile'}
        
        # We've already checked for reference matches and used zero tolerance
        # If we've reached here, there were no exact reference matches
        # We've already checked for FAK/VS pattern references
        # Here we continue with the standard payment tolerance check
        log_reconciliation(f"No exact reference matches found for line {st_line.id}, checking payment tolerance")
        
        # If we have any reference in the statement line, check for matches in amls
        # Create a combined list of FAK and VS references
        st_line_refs = fak_matches + vs_matches + ['VS' + vs for vs in vs_matches]
        
        # Also add versions without leading zeros for FAK references
        for fak in fak_matches:
            parts = fak.split('/')
            if len(parts) == 3:
                clean_num = parts[2].lstrip('0')
                if clean_num != parts[2]:
                    st_line_refs.append(f"{parts[0]}/{parts[1]}/{clean_num}")
        
        if st_line_refs and amls_values_list:
            log_reconciliation(f"Looking for these references in move lines: {st_line_refs}")
            
            for aml_values in amls_values_list:
                aml = aml_values['aml']
                move_ref = aml.move_id.ref or ''
                move_name = aml.move_id.name or ''
                move_text = move_ref + ' ' + move_name
                
                # Check for exact matches
                for ref in st_line_refs:
                    # First check for exact matches
                    if ref == move_ref or ref == move_name:
                        log_reconciliation(f"EXACT reference match ({ref}) found in {move_text} - allowing auto reconcile with ZERO tolerance")
                        return {'allow_auto_reconcile'}
                    # Then check for contains matches
                    elif ref in move_ref or ref in move_name:
                        log_reconciliation(f"Reference match ({ref}) found in {move_text} - allowing auto reconcile with ZERO tolerance")
                        return {'allow_auto_reconcile'}
            
        # If no invoice reference match, fall back to amount tolerance
        # If we have a single line and the difference is within tolerance, allow auto reconciliation
        if len(amls_values_list) == 1 and self.payment_tolerance_param:
            tolerance = self.payment_tolerance_param / 100.0  # Convert percentage to decimal
            diff_amount = abs(amount_curr_after_rec)
            base_amount = abs(st_line_amount_curr)
            if base_amount > 0 and (diff_amount / base_amount) <= tolerance:
                return {'allow_auto_reconcile'}

        # The payment amount is higher than the sum of invoices.
        # In that case, don't check the tolerance and don't try to generate any write-off.
        if amount_curr_after_rec > 0.0:
            return {'allow_auto_reconcile'}

        # No tolerance, reject the candidates.
        if self.payment_tolerance_param == 0:
            return {'rejected'}

        # If the tolerance is expressed as a fixed amount, check the residual payment amount doesn't exceed the
        # tolerance.
        if self.payment_tolerance_type == 'fixed_amount' and st_line_currency.compare_amounts(-amount_curr_after_rec, self.payment_tolerance_param) <= 0:
            return {'allow_write_off', 'allow_auto_reconcile'}

        # The tolerance is expressed as a percentage between 0 and 100.0.
        reconciled_percentage_left = (abs(amount_curr_after_rec / amls_amount_curr)) * 100.0
        if self.payment_tolerance_type == 'percentage' and st_line_currency.compare_amounts(reconciled_percentage_left, self.payment_tolerance_param) <= 0:
            return {'allow_write_off', 'allow_auto_reconcile'}

        return {'rejected'}

    def run_auto_reconciliation(self):
        """ Tries to auto-reconcile as many statements as possible within time limit
        arbitrary set to 3 minutes (the rest will be reconciled asynchronously with the regular cron).
        """
        # 'limit_time_real_cron' defaults to -1.
        # Manual fallback applied for non-POSIX systems where this key is disabled (set to None).
        cron_limit_time = tools.config['limit_time_real_cron'] or -1
        limit_time = cron_limit_time if 0 < cron_limit_time < 180 else 180
        self.env['account.bank.statement.line']._cron_try_auto_reconcile_statement_lines(limit_time=limit_time)
