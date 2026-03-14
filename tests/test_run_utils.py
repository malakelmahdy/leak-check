from leakcheck.common.run_utils import PROJECT_ROOT, resolve_project_path


def test_resolve_project_path_for_repo_relative_model_dir():
    resolved = resolve_project_path("model/best_model")
    assert resolved == str((PROJECT_ROOT / "model" / "best_model").resolve())


def test_resolve_project_path_leaves_absolute_paths_unchanged():
    absolute = str((PROJECT_ROOT / "configs" / "campaign.yaml").resolve())
    assert resolve_project_path(absolute) == absolute
