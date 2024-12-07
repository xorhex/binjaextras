from binaryninja.interaction import show_message_box
from binaryninja.log import Logger
from binaryninja import BinaryDataNotification, NotificationType, BinaryView, CoreSymbol, MessageBoxButtonResult, MessageBoxIcon, MessageBoxButtonSet, Settings, VariableSourceType
from binaryninja import BackgroundTaskThread, Variable
from binaryninjaui import UIActionContext 
from binaryninja.enums import InstructionTextTokenType
from binaryninja import typelibrary
from binaryninja import types as _types

from .constants import BE_SETTINGS__AUTOAPPLYFUNCTIONPROTOTYPE_ASK_BEFORE_OVERWRITING_USER_CHANGE, BE_SETTINGS__IMPORTTYPELIBRARY
from .constants import BE_SETTINGS__AUTOAPPLYFUNCTIONPROTOTYPE, BE_SETTINGS__AUTOAPPLYFUNCTIONPROTOTYPE_DONOT_OVERWRITE_USER_CHANGE

logger = Logger(session_id=0, logger_name=__name__)
       
class VariableTypeLookupTask(BackgroundTaskThread):
    def __init__(self, bv: BinaryView, current_variable: Variable):
        super().__init__(
            initial_progress_text="[BinjaExtras] Type lookup task starting...",
            can_cancel=False,
        )
        self.bv = bv
        self.current_variable = current_variable

    def run(self):
        name = self.current_variable.name.split('_')[0]
        t = get_function_prototype(self.bv, name)
        if t is not None:
            new_type = f'{t.get_string_before_name()} (* {name}) {t.get_string_after_name()}'
            self.current_variable.type = new_type
        else:
            logger.log_info(f'Type not found for {name}')
        self.bv.update_analysis_and_wait()
        self.finish()
        return

def type_lookup(context: UIActionContext):
    if context is not None:
        if context.view is not None:
            view = context.view
            a = view.actionContext()
            cur_var = Variable.from_identifier(a.function, a.token.token.value)
            VariableTypeLookupTask(a.binaryView, cur_var).start()

class AutoApplyFunctionPrototype(BinaryDataNotification):
    def __init__(self):
        super(AutoApplyFunctionPrototype, self).__init__(NotificationType.SymbolUpdated )
        self.settings = Settings()
        self.assignments = {}

    def symbol_updated(self, view: BinaryView, sym: CoreSymbol) -> None:
        logger.log_debug(f"symbol updated action triggered")
        if not self.settings.contains(BE_SETTINGS__AUTOAPPLYFUNCTIONPROTOTYPE):
            logger.log_debug(f"{BE_SETTINGS__AUTOAPPLYFUNCTIONPROTOTYPE} does not exists")
            return
        if not self.settings.get_bool(BE_SETTINGS__AUTOAPPLYFUNCTIONPROTOTYPE):
            logger.log_debug(f"{BE_SETTINGS__AUTOAPPLYFUNCTIONPROTOTYPE} not True")
            return
        logger.log_debug(f"symbol updated action taken")
        if func := view.get_function_at(sym.address):
            func_name = sym.name.split('_')[0]
            logger.log_debug(f"Function name changed to: {func_name}")
            t = get_function_prototype(view, func_name)
            if not (t is None):
                logger.log_debug(f"Type found for {func_name}")
                api_def = f'{t.get_string_before_name()} {sym.name}{t.get_string_after_name()}'
                if func.has_user_type:
                    logger.log_debug(f"{func_name} already has user type")
                    if self.settings.contains(BE_SETTINGS__AUTOAPPLYFUNCTIONPROTOTYPE_DONOT_OVERWRITE_USER_CHANGE):
                        if self.settings.get_bool(BE_SETTINGS__AUTOAPPLYFUNCTIONPROTOTYPE_DONOT_OVERWRITE_USER_CHANGE):
                            logger.log_debug(f"{func_name} already has user updated function prototype and has opted to auto skip overwriting the function prototype in this case.")
                            return
                    if self.settings.contains(BE_SETTINGS__AUTOAPPLYFUNCTIONPROTOTYPE_ASK_BEFORE_OVERWRITING_USER_CHANGE):
                        if self.settings.get_bool(BE_SETTINGS__AUTOAPPLYFUNCTIONPROTOTYPE_ASK_BEFORE_OVERWRITING_USER_CHANGE):
                            if show_message_box("Overwrite Function Definition", f"Function definition has been modified, still want to apply the function definition for {sym.name}?", MessageBoxButtonSet.YesNoButtonSet, MessageBoxIcon.WarningIcon) != MessageBoxButtonResult.YesButton:
                                logger.log_info(f"User chose not to update the function definition for: {hex(sym.address)} {sym.name}")
                                return 
                func.set_user_type(api_def)
                logger.log_info(f"Symbol Updated: {hex(sym.address)} {sym.name}: {api_def}")
            else:
                logger.log_debug(f"Type not found for: {func_name} at {hex(sym.address)}")
        else:
            logger.log_debug(f"Function not found at: {hex(sym.address)}")

def get_function_prototype(bv: BinaryView, func_name: str) -> None | tuple[typelibrary.TypeLibrary, _types.Type]:
    t = bv.import_library_object(func_name)
    if t is None:
        settings = Settings()
        if settings.contains(BE_SETTINGS__IMPORTTYPELIBRARY):
            if settings.get_bool(BE_SETTINGS__IMPORTTYPELIBRARY):
                for type_library in bv.platform.type_libraries:
                    if type_library.get_named_object(func_name) is not None:
                        logger.log_info(f"Found {func_name} in {type_library}, adding the type library")
                        bv.add_type_library(type_library)
                        t = bv.import_library_object(func_name)
                        break
    return t

