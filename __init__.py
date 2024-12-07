from binaryninja.settings import Settings
from binaryninja.interaction import show_message_box
from binaryninja.log import Logger
from binaryninja import MessageBoxIcon, MessageBoxButtonSet, BinaryView, BinaryViewType
from binaryninja.plugin import PluginCommand
from binaryninjaui import UIActionHandler, UIAction, Menu, UIActionContext
from .actions import AutoApplyFunctionPrototype 
from .constants import *
from .actions import *

import json
logger = Logger(session_id=0, logger_name=__name__)


BINJA_EXTRAS_PLUGIN_SETTINGS: list[tuple[str, dict[str, object]]] = [
	(
		BE_SETTINGS__AUTOAPPLYFUNCTIONPROTOTYPE,
		{
		"title": "Auto Apply Function Prototype",
		"type": "boolean",
		"default": False,
		"description": "Enable this to apply function prototype when the function name is changed to match a library function name",
		"ignore": ["SettingsProjectScope", "SettingsResourceScope"],
		},
	),
	(
		BE_SETTINGS__AUTOAPPLYFUNCTIONPROTOTYPE_ASK_BEFORE_OVERWRITING_USER_CHANGE,
		{
		"title": "Auto Apply Function Prototype Confirmation",
		"type": "boolean",
		"default": False,
		"description": "Enable this to have the auto apply function prototype feature ask before overwriting a user modified function prototype. 'Do Not Overwrite User Modified Function' must NOT be checked for this to fire.",
		"ignore": ["SettingsProjectScope", "SettingsResourceScope"],
		},
	),
	(
		BE_SETTINGS__AUTOAPPLYFUNCTIONPROTOTYPE_DONOT_OVERWRITE_USER_CHANGE,
		{
		"title": "Do Not Overwrite User Modified Function",
		"type": "boolean",
		"default": True,
		"description": "When enabled, this plugin will no change any function whose function prototype was already modified by the user",
		"ignore": ["SettingsProjectScope", "SettingsResourceScope"],
		},
	),
	(
        BE_SETTINGS__APPLYFUNCTIONPROTOTYPECONTEXTMENU,
		{
		"title": "Apply Function Prototype to Variable",
		"type": "boolean",
		"default": True,
		"description": f"Allow the context menu item '{CONTEXT_MENU_APPLY_TYPE}' to be shown when highlighting a variable",
		"ignore": ["SettingsProjectScope", "SettingsResourceScope"],
		},
	),
	(
        BE_SETTINGS__IMPORTTYPELIBRARY,
		{
		"title": "Import Type Library",
		"type": "boolean",
		"default": True,
		"description": f"Search type libraries for matching function name and load it when the type library is not found in the already loaded libraries",
		"ignore": ["SettingsProjectScope", "SettingsResourceScope"],
		},
	),
]

def register_settings() -> bool:
    _ = Settings().register_group("binjaextras", "BinjaExtras")
    for setting_name, setting_properties in BINJA_EXTRAS_PLUGIN_SETTINGS:
        if not Settings().register_setting(
            setting_name, json.dumps(setting_properties)
        ):
            logger.log_error(
                f"Failed to register setting with name {setting_name}, properties {setting_properties}"
            )
            logger.log_error(f"Abandoning setting registration")
            return False
    return True

if not register_settings():
    logger.log_error("Failed to initialize HashDB plugin settings")


def about(bv: BinaryView):
    _ = show_message_box("BinjaExtras About", f"This plugin adds various features (currently 2) to binaryninja to aid in malware analysis. Check BinjaExtras under Settings on how to configure them.", MessageBoxButtonSet.OKButtonSet, MessageBoxIcon.InformationIcon)

PluginCommand.register("BinjaExtras\\About", "Additional almost random features added to aid in malware analysis", about)

def autoapplyfunctionprototype(bv: BinaryView):
    logger.log_debug(f'binaryview call back called')
    bv.register_notification(AutoApplyFunctionPrototype())
            
BinaryViewType.add_binaryview_initial_analysis_completion_event(autoapplyfunctionprototype)

def context_menu_creation(ctx: UIActionContext):
    settings = Settings()
    if not settings.contains(BE_SETTINGS__APPLYFUNCTIONPROTOTYPECONTEXTMENU):
        return
    if not settings.get_bool(BE_SETTINGS__APPLYFUNCTIONPROTOTYPECONTEXTMENU):
        return
    if ctx is not None:
        view = ctx.view
        if view is not None:
            context_menu = view.contextMenu()
            if len(context_menu.getActions().keys()) == 0:
                return ctx.context and ctx.binaryView

            if ctx.token.token:
                token = ctx.token.token
                if current_function := ctx.function:
                    if token.type in [InstructionTextTokenType.LocalVariableToken]:
                        if not CONTEXT_MENU_APPLY_TYPE in view.contextMenu().getActions().keys():
                            context_menu.addAction(CONTEXT_MENU_APPLY_TYPE, "", 0)
                            logger.log_debug(f"Added BinjaExtras context menu item: '{CONTEXT_MENU_APPLY_TYPE}'")
                    else:
                        if CONTEXT_MENU_APPLY_TYPE in view.contextMenu().getActions().keys():
                            context_menu.removeAction(CONTEXT_MENU_APPLY_TYPE)
                            logger.log_debug(f"Removed BinjaExtras context menu item: '{CONTEXT_MENU_APPLY_TYPE}'")
            return ctx.context and ctx.binaryView
    else:
        logger.log_error("Failed to initialize BinjaExtras context menu")
        return False

UIAction.registerAction(CONTEXT_MENU_APPLY_TYPE)
UIActionHandler.globalActions().bindAction(CONTEXT_MENU_APPLY_TYPE, UIAction(actions.type_lookup, context_menu_creation))
Menu.mainMenu("Plugins").addAction(CONTEXT_MENU_APPLY_TYPE, "", 0)
